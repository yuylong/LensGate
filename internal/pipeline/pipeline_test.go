package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lensgate/internal/config"
	"lensgate/internal/detect"
	"lensgate/internal/model"
	"lensgate/internal/proto/openai"
	"lensgate/internal/store"
)

// 客户端指纹必须完整贯通到对外输出的 Flow，且不影响协议置信度。
func TestToFlowCarriesClientFingerprint(t *testing.T) {
	p := &Pipeline{}
	now := time.Now()
	sess := &model.Session{
		ID:        "flow-1",
		Meta:      model.ConnMeta{Ingress: "explicit"},
		StartedAt: now,
		EndedAt:   now,
		Request: model.RequestInfo{
			Method: http.MethodPost,
			Host:   "api.openai.com",
			Path:   "/v1/chat/completions",
		},
	}

	info := openai.DetectClient(http.Header{
		"X-Stainless-Lang": []string{"python"},
		"User-Agent":       []string{"OpenAI/Python 1.40.0"},
	})
	sess.Classification = model.Classification{
		ProtocolFamily: "openai",
		APIVariant:     openai.VariantChat,
		Confidence:     openai.ConfidenceConfirmed,
		ClientKind:     info.Kind,
		ClientDetail:   info.Detail,
		ClientReason:   strings.Join(info.Evidence, " · "),
	}

	flow := p.toFlow(sess, "api.openai.com", "/v1/chat/completions")

	if flow.ClientKind != openai.ClientOpenAIPy {
		t.Fatalf("client_kind = %q, want %q", flow.ClientKind, openai.ClientOpenAIPy)
	}
	if flow.ClientDetail != "OpenAI/Python 1.40.0" {
		t.Fatalf("client_detail = %q", flow.ClientDetail)
	}
	if flow.ClientReason == "" {
		t.Fatal("client_reason 不应为空")
	}
	if flow.Confidence != openai.ConfidenceConfirmed {
		t.Fatalf("confidence 被改动：%q", flow.Confidence)
	}
}

// 流式 chat completions 请求在转发前应被注入 stream_options.include_usage，
// 且 Content-Length 与改写后的请求体一致；上游返回的 usage chunk 应聚合进 Flow。
func TestHandleInjectsStreamUsage(t *testing.T) {
	tests := []struct {
		name            string
		requestBody     string
		wantInjected    bool
		wantUsageInFlow bool
	}{
		{
			name:            "未设置 stream_options 时注入",
			requestBody:     `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`,
			wantInjected:    true,
			wantUsageInFlow: true,
		},
		{
			name:            "已设置 stream_options 时不改写",
			requestBody:     `{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false},"messages":[{"role":"user","content":"hi"}]}`,
			wantInjected:    false,
			wantUsageInFlow: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody []byte
			var gotContentLength int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				gotContentLength = r.ContentLength
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
				_, _ = w.Write([]byte("data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}\n\n"))
				_, _ = w.Write([]byte("data: [DONE]\n\n"))
			}))
			defer upstream.Close()

			cfg := config.Default()
			st, err := store.New("", 10, 10)
			if err != nil {
				t.Fatalf("store.New: %v", err)
			}
			p := New(cfg, st, detect.New(nil), nil)
			defer p.Close()

			req := httptest.NewRequest(http.MethodPost, "http://"+upstream.Listener.Addr().String()+"/v1/chat/completions", strings.NewReader(tt.requestBody))
			req.Header.Set("Authorization", "Bearer sk-test")
			rec := httptest.NewRecorder()
			p.Handle(context.Background(), model.ConnMeta{Ingress: "explicit"}, rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			var probe struct {
				StreamOptions struct {
					IncludeUsage bool `json:"include_usage"`
				} `json:"stream_options"`
			}
			if err := json.Unmarshal(gotBody, &probe); err != nil {
				t.Fatalf("上游收到的请求体不是合法 JSON：%v", err)
			}
			if probe.StreamOptions.IncludeUsage != tt.wantInjected {
				t.Fatalf("上游收到 include_usage = %v, want %v；body=%s", probe.StreamOptions.IncludeUsage, tt.wantInjected, gotBody)
			}
			if gotContentLength != int64(len(gotBody)) {
				t.Fatalf("Content-Length = %d, want %d（与转发体一致）", gotContentLength, len(gotBody))
			}

			flows := st.Flows(10)
			if len(flows) != 1 {
				t.Fatalf("flows = %d, want 1", len(flows))
			}
			flow := flows[0]
			var markerSeen bool
			for _, s := range flow.ParseStatus {
				if s == "stream_usage_injected" {
					markerSeen = true
				}
			}
			if markerSeen != tt.wantInjected {
				t.Fatalf("stream_usage_injected 标记 = %v, want %v", markerSeen, tt.wantInjected)
			}
			if tt.wantUsageInFlow && flow.Usage == nil {
				t.Fatalf("usage 未入库：%+v", flow.ParseStatus)
			}
			if tt.wantUsageInFlow && flow.Usage.Total != 8 {
				t.Fatalf("usage.Total = %d, want 8", flow.Usage.Total)
			}
		})
	}
}

// 客户端取消必须传播到上游：否则客户端早已放弃（或超时重试）后，
// 网关仍占用上游连接无限等待，表现为“空闲很久后的第一发请求挂起、
// 手动停止后重试反而很快”。
func TestHandleClientCancelPropagatesToUpstream(t *testing.T) {
	var (
		mu       sync.Mutex
		canceled bool
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 读完整请求体，服务端才能在后台侦测客户端断开并取消上下文。
		_, _ = io.ReadAll(r.Body)
		select {
		case <-r.Context().Done():
			mu.Lock()
			canceled = true
			mu.Unlock()
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()

	cfg := config.Default()
	st, err := store.New("", 10, 10)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	p := New(cfg, st, detect.New(nil), nil)
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "http://"+upstream.Listener.Addr().String()+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer sk-test")

	started := time.Now()
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	rec := httptest.NewRecorder()
	p.Handle(ctx, model.ConnMeta{Ingress: "explicit"}, rec, req)
	elapsed := time.Since(started)

	if elapsed > 3*time.Second {
		t.Fatalf("Handle 耗时 %v：客户端取消未传播到上游，请求仍在等待上游响应", elapsed)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}

	// 服务端感知断开是异步的，轮询等待上游上下文被取消。
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		c := canceled
		mu.Unlock()
		if c {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("上游请求上下文未被取消：客户端取消没有传播到上游")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// 上游长时间不返回响应头时应按 upstream_header_timeout_seconds 返回 502，
// 而不是无限挂起。
func TestHandleUpstreamHeaderTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.UpstreamHeaderTimeoutSeconds = 1
	st, err := store.New("", 10, 10)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	p := New(cfg, st, detect.New(nil), nil)
	defer p.Close()

	req := httptest.NewRequest(http.MethodPost, "http://"+upstream.Listener.Addr().String()+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer sk-test")

	started := time.Now()
	rec := httptest.NewRecorder()
	p.Handle(context.Background(), model.ConnMeta{Ingress: "explicit"}, rec, req)
	elapsed := time.Since(started)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if elapsed >= 2500*time.Millisecond {
		t.Fatalf("耗时 %v，未按 upstream_header_timeout_seconds 及时失败", elapsed)
	}

	flows := st.Flows(10)
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	found := false
	for _, s := range flows[0].ParseStatus {
		if s == "upstream_error" {
			found = true
		}
	}
	if !found {
		t.Fatalf("parse_status 缺少 upstream_error：%v", flows[0].ParseStatus)
	}
}
