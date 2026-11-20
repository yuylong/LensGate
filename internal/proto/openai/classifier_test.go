package openai

import (
	"net/http"
	"testing"

	"lensgate/internal/model"
)

func chatBody() []byte {
	return []byte(`{"model":"gpt-4o-mini","stream":false,"messages":[{"role":"user","content":"你好"}]}`)
}

func TestClassifyRequestLevels(t *testing.T) {
	auth := http.Header{"Authorization": []string{"Bearer sk-demo"}}

	cases := []struct {
		name     string
		in       RequestInput
		wantConf string
		wantVar  string
		wantFam  string
	}{
		{
			name: "known host + auth + schema",
			in: RequestInput{
				Method: http.MethodPost, Host: "api.openai.com", Path: "/v1/chat/completions",
				Headers: auth, Body: chatBody(), KnownHost: true,
			},
			wantConf: ConfidenceConfirmed, wantVar: VariantChat, wantFam: "openai",
		},
		{
			name: "path + schema only",
			in: RequestInput{
				Method: http.MethodPost, Host: "proxy.internal", Path: "/v1/chat/completions",
				Headers: http.Header{}, Body: chatBody(),
			},
			wantConf: ConfidenceCompatible, wantVar: VariantChat, wantFam: "openai",
		},
		{
			name: "unknown path with OpenAI body",
			in: RequestInput{
				Method: http.MethodPost, Host: "unknown.example", Path: "/custom/llm",
				Headers: http.Header{}, Body: chatBody(),
			},
			wantConf: ConfidenceSuspected, wantFam: "openai-compatible",
		},
		{
			name: "generic json",
			in: RequestInput{
				Method: http.MethodPost, Host: "example.com", Path: "/api/orders",
				Headers: auth, Body: []byte(`{"order_id":"A-1","amount":99}`),
			},
			wantConf: ConfidenceNotAI, wantFam: "unknown",
		},
		{
			name: "jsonrpc tunnel messages",
			in: RequestInput{
				Method: http.MethodPost, Host: "api5-normal.mchost.guru",
				Path:   "/custom_model/tunnel/d0558397-4119-4712-96df-daaecef871f2/messages",
				Headers: http.Header{}, Body: []byte(`{"messages":[{"jsonrpc":"2.0","method":"sse.delta","params":{"event":"message","payload":{"object":"chat.completion.chunk"}}},{"jsonrpc":"2.0","method":"sse.end","params":{"finish_reason":"done"}}]}`),
			},
			wantConf: ConfidenceNotAI, wantFam: "unknown",
		},
		{
			name: "messages without role",
			in: RequestInput{
				Method: http.MethodPost, Host: "relay.example", Path: "/tunnel/messages",
				Headers: http.Header{}, Body: []byte(`{"messages":[{"text":"hi"}]}`),
			},
			wantConf: ConfidenceNotAI, wantFam: "unknown",
		},
		{
			name: "messages not array",
			in: RequestInput{
				Method: http.MethodPost, Host: "relay.example", Path: "/tunnel/messages",
				Headers: http.Header{}, Body: []byte(`{"messages":"batch"}`),
			},
			wantConf: ConfidenceNotAI, wantFam: "unknown",
		},
		{
			name: "messages empty array",
			in: RequestInput{
				Method: http.MethodPost, Host: "relay.example", Path: "/tunnel/messages",
				Headers: http.Header{}, Body: []byte(`{"messages":[]}`),
			},
			wantConf: ConfidenceNotAI, wantFam: "unknown",
		},
		{
			name: "azure deployment path",
			in: RequestInput{
				Method: http.MethodPost, Host: "my-resource.openai.azure.com",
				Path:    "/openai/deployments/gpt-4o/chat/completions",
				Headers: http.Header{"Api-Key": []string{"demo"}}, Body: chatBody(),
			},
			wantConf: ConfidenceConfirmed, wantVar: VariantChat, wantFam: "openai",
		},
		{
			name: "path only",
			in: RequestInput{
				Method: http.MethodPost, Host: "unknown.example", Path: "/v1/chat/completions",
				Headers: http.Header{}, Body: []byte(`not-json`),
			},
			wantConf: ConfidenceSuspected, wantVar: VariantChat, wantFam: "openai",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyRequest(tc.in)
			if got.Classification.Confidence != tc.wantConf {
				t.Fatalf("confidence = %s, want %s (reason: %s)", got.Classification.Confidence, tc.wantConf, got.Classification.Reason)
			}
			if tc.wantVar != "" && got.Classification.APIVariant != tc.wantVar {
				t.Fatalf("variant = %s, want %s", got.Classification.APIVariant, tc.wantVar)
			}
			if got.Classification.ProtocolFamily != tc.wantFam {
				t.Fatalf("family = %s, want %s", got.Classification.ProtocolFamily, tc.wantFam)
			}
		})
	}
}

func TestRefineWithResponse(t *testing.T) {
	resp := &ParsedResponse{Strong: true, StrongReason: "object:chat.completion", Object: "chat.completion"}

	base := ClassifyRequest(RequestInput{
		Method: http.MethodPost, Host: "unknown.example", Path: "/custom/llm",
		Body: chatBody(),
	})
	upgraded := RefineWithResponse(base.Classification, resp, false, true, false)
	if upgraded.Confidence != ConfidenceCompatible {
		t.Fatalf("expected compatible, got %s", upgraded.Confidence)
	}
	if upgraded.APIVariant != VariantChat {
		t.Fatalf("expected variant chat, got %s", upgraded.APIVariant)
	}

	noSignal := RefineWithResponse(model.Classification{ProtocolFamily: "unknown", Confidence: ConfidenceNotAI}, resp, false, false, false)
	if noSignal.Confidence != ConfidenceSuspected {
		t.Fatalf("expected suspected, got %s", noSignal.Confidence)
	}
}
