package pipeline

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"lensgate/internal/model"
	"lensgate/internal/proto/openai"
)

// 详情必须把管线里已有的解析结果完整带出，同时对头部与正文脱敏。
func TestBuildFlowDetail(t *testing.T) {
	body := []byte(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"system","content":"你是企业助手"},{"role":"user","content":"联系 zhangwei@example.com 并用 api_key=sk-proj-demo1234567890abcdefghijklmnop 调用"}]}`)
	req, err := openai.ParseRequest(body)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	sess := &model.Session{
		ID:   "flow-1",
		Meta: model.ConnMeta{Ingress: "explicit", IsTLS: true, ALPN: []string{"h2"}},
		Request: model.RequestInfo{
			Method: http.MethodPost,
			Host:   "api.openai.com",
			Path:   "/v1/chat/completions",
			Query:  "api-version=2024-10-21",
			Headers: http.Header{
				"Authorization": []string{"Bearer sk-proj-demo1234567890abcdefghijklmnop"},
				"Api-Key":       []string{"demo-azure-key"},
				"User-Agent":    []string{"OpenAI/Python 1.40.0"},
			},
			ContentType:   "application/json",
			Body:          body,
			BodyTruncated: true,
		},
		Response: model.ResponseInfo{
			Status:      200,
			Headers:     http.Header{"Content-Type": []string{"text/event-stream"}},
			ContentType: "text/event-stream",
			SSE: []model.SSEEvent{
				{Data: `{"choices":[{"delta":{"content":"你好"},"finish_reason":"stop"}]}`},
				{Data: "[DONE]"},
			},
			Chunks:    4,
			Completed: true,
		},
	}
	resp := &openai.ParsedResponse{Object: "chat.completion.chunk", Text: "你好", FinishReason: "stop"}
	flow := model.Flow{ID: "flow-1", Host: "api.openai.com", Path: "/v1/chat/completions", RequestSummary: "hi"}

	detail := buildFlowDetail(flow, sess, req, resp)

	if !detail.IsTLS || len(detail.ALPN) != 1 || detail.ALPN[0] != "h2" {
		t.Fatalf("连接元数据未带出：tls=%v alpn=%v", detail.IsTLS, detail.ALPN)
	}
	if detail.Flow.ID != "flow-1" || detail.Flow.RequestSummary != "hi" {
		t.Fatalf("基础 Flow 未带出：%+v", detail.Flow)
	}
	if detail.Request.Query != "api-version=2024-10-21" || !detail.Request.BodyTruncated {
		t.Fatalf("请求基础字段异常：%+v", detail.Request)
	}
	if !json.Valid([]byte(detail.Request.Body)) {
		t.Fatalf("脱敏后的请求体应为合法 JSON：%s", detail.Request.Body)
	}
	if strings.Contains(detail.Request.Body, "sk-proj-demo") || strings.Contains(detail.Request.Body, "zhangwei@example.com") {
		t.Fatalf("请求体未脱敏：%s", detail.Request.Body)
	}

	if got := headerValue(detail.Request.Headers, "Authorization"); got != "Bearer ***" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer ***")
	}
	if got := headerValue(detail.Request.Headers, "Api-Key"); got != "***" {
		t.Fatalf("Api-Key = %q, want ***", got)
	}
	if got := headerValue(detail.Request.Headers, "User-Agent"); got != "OpenAI/Python 1.40.0" {
		t.Fatalf("User-Agent 不应被改动：%q", got)
	}

	if len(detail.Request.Messages) != 2 || detail.Request.Messages[1].Role != "user" {
		t.Fatalf("messages 未解析：%+v", detail.Request.Messages)
	}
	if content := detail.Request.Messages[1].Content; strings.Contains(content, "zhangwei@example.com") || strings.Contains(content, "sk-proj-demo") {
		t.Fatalf("messages 内容脱敏异常：%q", content)
	}
	if detail.Request.Model != "gpt-4o-mini" || !detail.Request.Stream {
		t.Fatalf("请求模型/流式标记异常：%+v", detail.Request)
	}

	if detail.Response.Status != 200 || !detail.Response.Completed || detail.Response.Chunks != 4 {
		t.Fatalf("响应基础字段异常：%+v", detail.Response)
	}
	if detail.Response.Text != "你好" || detail.Response.FinishReason != "stop" {
		t.Fatalf("响应聚合结果异常：%+v", detail.Response)
	}
	if len(detail.Response.SSE) != 2 || detail.Response.SSE[1].Data != "[DONE]" {
		t.Fatalf("SSE 事件未带出：%+v", detail.Response.SSE)
	}
	if !json.Valid([]byte(detail.Response.SSE[0].Data)) {
		t.Fatalf("SSE data 应为合法 JSON：%s", detail.Response.SSE[0].Data)
	}
}

func TestBuildFlowDetailWithoutParsedData(t *testing.T) {
	sess := &model.Session{
		ID: "flow-2",
		Request: model.RequestInfo{
			Method:  http.MethodGet,
			Host:    "example.com",
			Path:    "/",
			Headers: http.Header{"Cookie": []string{"session=secret-value"}},
			Body:    []byte("not json token=sk-proj-demo1234567890abcdefghijklmnop"),
		},
	}
	detail := buildFlowDetail(model.Flow{ID: "flow-2"}, sess, nil, nil)

	if len(detail.Request.Messages) != 0 || len(detail.Request.Tools) != 0 {
		t.Fatalf("未解析时不应有 messages/tools：%+v", detail.Request)
	}
	if got := headerValue(detail.Request.Headers, "Cookie"); got != "***" {
		t.Fatalf("Cookie = %q, want ***", got)
	}
	if strings.Contains(detail.Request.Body, "sk-proj-demo") {
		t.Fatalf("非 JSON 正文未脱敏：%s", detail.Request.Body)
	}
}

func TestRedactHeaderValue(t *testing.T) {
	cases := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{"bearer", "Authorization", "Bearer sk-proj-demo1234567890abcdefghijklmnop", "Bearer ***"},
		{"api key", "X-Api-Key", "demo-key", "***"},
		{"cookie", "Cookie", "session=abc", "***"},
		{"set cookie", "Set-Cookie", "sid=1; HttpOnly", "***"},
		{"plain header", "User-Agent", "curl/8.7.1", "curl/8.7.1"},
		{"credential inside header", "User-Agent", "agent sk-proj-demo1234567890abcdefghijklmnop", "agent sk-p***mnop"},
		{"empty sensitive", "Authorization", "  ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redactHeaderValue(c.header, c.value); got != c.want {
				t.Fatalf("redactHeaderValue(%q, %q) = %q, want %q", c.header, c.value, got, c.want)
			}
		})
	}
}

func TestRedactJSONBody(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantValid  bool
		notContain string
	}{
		{"json", `{"email":"zhangwei@example.com","token":"sk-proj-demo1234567890abcdefghijklmnop"}`, true, "zhangwei@example.com"},
		{"nested json", `{"messages":[{"content":"call 13800138000"}]}`, true, "13800138000"},
		{"non json", "data: sk-proj-demo1234567890abcdefghijklmnop", false, "sk-proj-demo"},
		{"empty", "", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redactJSONBody([]byte(c.in))
			if c.wantValid && !json.Valid([]byte(got)) {
				t.Fatalf("应为合法 JSON：%s", got)
			}
			if c.notContain != "" && strings.Contains(got, c.notContain) {
				t.Fatalf("未脱敏 %q：%s", c.notContain, got)
			}
		})
	}
}

func headerValue(headers []model.Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			if len(h.Values) == 0 {
				return ""
			}
			return h.Values[0]
		}
	}
	return ""
}
