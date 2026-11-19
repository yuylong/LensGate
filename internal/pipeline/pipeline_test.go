package pipeline

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"lensgate/internal/model"
	"lensgate/internal/proto/openai"
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
