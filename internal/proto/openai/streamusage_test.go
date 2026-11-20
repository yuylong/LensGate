package openai

import (
	"encoding/json"
	"testing"
)

func TestInjectStreamUsage(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		wantOK bool
	}{
		{
			name:   "流式请求注入",
			body:   `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`,
			wantOK: true,
		},
		{
			name:    "客户端已设置 stream_options 不覆盖",
			body:    `{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false},"messages":[]}`,
			wantOK:  false,
		},
		{
			name:    "非流式不注入",
			body:    `{"model":"gpt-4o","stream":false,"messages":[]}`,
			wantOK:  false,
		},
		{
			name:    "缺少 stream 字段不注入",
			body:    `{"model":"gpt-4o","messages":[]}`,
			wantOK:  false,
		},
		{
			name:    "stream 非布尔不注入",
			body:    `{"model":"gpt-4o","stream":"true","messages":[]}`,
			wantOK:  false,
		},
		{
			name:    "非法 JSON 不注入",
			body:    `{"model":"gpt-4o","stream":true`,
			wantOK:  false,
		},
		{
			name:    "非对象 JSON 不注入",
			body:    `[{"stream":true}]`,
			wantOK:  false,
		},
		{
			name:    "空请求体不注入",
			body:    ``,
			wantOK:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, ok := InjectStreamUsage([]byte(tt.body))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if string(out) != tt.body {
					t.Fatalf("未注入时请求体被改动：%q", out)
				}
				return
			}
			var probe struct {
				Model         string          `json:"model"`
				Messages      json.RawMessage `json:"messages"`
				StreamOptions struct {
					IncludeUsage bool `json:"include_usage"`
				} `json:"stream_options"`
			}
			if err := json.Unmarshal(out, &probe); err != nil {
				t.Fatalf("注入后请求体不是合法 JSON：%v", err)
			}
			if !probe.StreamOptions.IncludeUsage {
				t.Fatalf("stream_options.include_usage 不为 true：%s", out)
			}
			if probe.Model != "gpt-4o" || len(probe.Messages) == 0 {
				t.Fatalf("注入破坏了原有字段：%s", out)
			}
		})
	}
}
