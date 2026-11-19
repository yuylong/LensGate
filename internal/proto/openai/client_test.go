package openai

import (
	"net/http"
	"testing"
)

func TestDetectClient(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want string
	}{
		{
			name: "浏览器地址栏直接访问",
			h: http.Header{
				"Sec-Fetch-Mode": []string{"navigate"},
				"Sec-Fetch-User": []string{"?1"},
				"User-Agent":     []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0"},
			},
			want: ClientBrowser,
		},
		{
			name: "浏览器页面内 fetch",
			h: http.Header{
				"Sec-Fetch-Mode": []string{"cors"},
				"Origin":         []string{"https://app.example.com"},
				"User-Agent":     []string{"Mozilla/5.0 (Macintosh) Safari/605.1.15"},
			},
			want: ClientBrowserJS,
		},
		{
			name: "仅 Sec-CH-UA 也认定为浏览器",
			h: http.Header{
				"Sec-Ch-Ua":  []string{`"Chromium";v="126"`},
				"User-Agent": []string{"Mozilla/5.0"},
			},
			want: ClientBrowserJS,
		},
		{
			name: "OpenAI Python SDK stainless",
			h: http.Header{
				"X-Stainless-Lang":    []string{"python"},
				"X-Stainless-Runtime": []string{"CPython"},
				"User-Agent":          []string{"OpenAI/Python 1.40.0"},
			},
			want: ClientOpenAIPy,
		},
		{
			name: "OpenAI Node SDK stainless",
			h: http.Header{
				"X-Stainless-Lang": []string{"js"},
				"User-Agent":       []string{"OpenAI/NodeJS/4.60.0"},
			},
			want: ClientOpenAINode,
		},
		{
			name: "其他语言 SDK",
			h: http.Header{
				"X-Stainless-Lang": []string{"go"},
			},
			want: ClientSDKOther,
		},
		{
			name: "旧版 Python SDK UA",
			h: http.Header{
				"User-Agent": []string{"OpenAI/Python 0.28.1"},
			},
			want: ClientOpenAIPy,
		},
		{
			name: "LangChain 特征头",
			h: http.Header{
				"X-Langchain-Id": []string{"run-123"},
				"User-Agent":     []string{"OpenAI/Python 1.40.0"},
			},
			want: ClientLangChain,
		},
		{
			name: "LlamaIndex UA",
			h: http.Header{
				"User-Agent": []string{"llama-index/0.11.0"},
			},
			want: ClientLlamaIdx,
		},
		{
			name: "OpenRouter 归因头",
			h: http.Header{
				"X-Title": []string{"my-agent"},
			},
			want: ClientOpenRouter,
		},
		{
			name: "curl",
			h: http.Header{
				"User-Agent": []string{"curl/8.7.1"},
			},
			want: ClientCurl,
		},
		{
			name: "Postman",
			h: http.Header{
				"User-Agent": []string{"PostmanRuntime/7.39.0"},
			},
			want: ClientPostman,
		},
		{
			name: "python requests",
			h: http.Header{
				"User-Agent": []string{"python-requests/2.32.3"},
			},
			want: ClientPythonHTTP,
		},
		{
			name: "python httpx",
			h: http.Header{
				"User-Agent": []string{"python-httpx/0.27.0"},
			},
			want: ClientPythonHTTP,
		},
		{
			name: "Go 程序",
			h: http.Header{
				"User-Agent": []string{"Go-http-client/1.1"},
			},
			want: ClientGoHTTP,
		},
		{
			name: "Node undici",
			h: http.Header{
				"User-Agent": []string{"undici"},
			},
			want: ClientNodeHTTP,
		},
		{
			name: "PowerShell",
			h: http.Header{
				"User-Agent": []string{"Mozilla/5.0 (Windows NT; Windows NT 10.0; zh-CN) WindowsPowerShell/5.1.22621.4249"},
			},
			want: ClientPowerShell,
		},
		{
			name: "浏览器 UA 但缺失 Sec-Fetch",
			h: http.Header{
				"User-Agent": []string{"Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"},
			},
			want: ClientBrowser,
		},
		{
			name: "无任何指纹",
			h:    http.Header{},
			want: ClientUnknown,
		},
		{
			name: "nil 头",
			h:    nil,
			want: ClientUnknown,
		},
		// ---- 预置的 AI 应用 / Agent ----
		{
			name: "Claude Code CLI",
			h: http.Header{
				"User-Agent": []string{"claude-cli/1.0.60 (external, cli)"},
			},
			want: ClientClaudeCode,
		},
		{
			name: "GitHub Copilot Chat",
			h: http.Header{
				"User-Agent": []string{"GitHubCopilotChat/0.22.0"},
			},
			want: ClientCopilot,
		},
		{
			name: "Trae IDE",
			h: http.Header{
				"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Trae/1.0.0 Electron/30.0.0 Chrome/124.0 Safari/537.36"},
			},
			want: ClientTrae,
		},
		// 真实抓到的 Trae 国内版 UA：Electron + TraeCN。
		{
			name: "TraeCN 桌面端",
			h: http.Header{
				"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) TraeCN/1.107.1 Chrome/142.0.7444.235 Electron/39.2.7 Safari/537.36"},
			},
			want: ClientTrae,
		},
		// Trae 内嵌网络库 TTNet 上报的 UA。
		{
			name: "TraeClient/TTNet",
			h: http.Header{
				"User-Agent": []string{"TraeClient/TTNet"},
			},
			want: ClientTrae,
		},
		// Electron 应用带 Sec-Fetch（桌面端渲染进程）时，产品指纹必须优先于浏览器判断。
		{
			name: "Trae 带 Sec-Fetch",
			h: http.Header{
				"User-Agent":     []string{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 TraeCN/1.107.1 Chrome/142.0 Electron/39.2.7 Safari/537.36"},
				"Sec-Fetch-Mode": []string{"no-cors"},
				"Sec-Fetch-Site": []string{"none"},
			},
			want: ClientTrae,
		},
		{
			name: "Cursor",
			h: http.Header{
				"User-Agent": []string{"Cursor/0.45.11"},
			},
			want: ClientCursor,
		},
		{
			name: "Windsurf",
			h: http.Header{
				"User-Agent": []string{"Windsurf/1.2.3"},
			},
			want: ClientWindsurf,
		},
		{
			name: "Codex CLI",
			h: http.Header{
				"User-Agent": []string{"codex_cli_rs/0.20.0"},
			},
			want: ClientCodex,
		},
		{
			name: "Gemini CLI",
			h: http.Header{
				"User-Agent": []string{"GeminiCLI/0.1.9"},
			},
			want: ClientGeminiCLI,
		},
		{
			name: "Electron 应用（未声明产品）",
			h: http.Header{
				"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0) Electron/31.0.0 Chrome/126.0 Safari/537.36"},
			},
			want: ClientElectron,
		},
		// 用户实际遇到的场景：Trae 服务端用 CloudWeGo Hertz。
		{
			name: "CloudWeGo Hertz",
			h: http.Header{
				"User-Agent": []string{"hertz"},
			},
			want: ClientHertz,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectClient(tc.h)
			if got.Kind != tc.want {
				t.Fatalf("kind = %s, want %s (evidence: %v)", got.Kind, tc.want, got.Evidence)
			}
		})
	}
}

// unknown 时必须保留原始 UA，供控制台直接展示，避免丢失排查线索。
func TestDetectClientKeepsRawUADetail(t *testing.T) {
	const ua = "SomeCustomAgent/2.1 (build 42)"
	got := DetectClient(http.Header{"User-Agent": []string{ua}})
	if got.Kind != ClientUnknown {
		t.Fatalf("kind = %s, want unknown", got.Kind)
	}
	if got.Detail != ua {
		t.Fatalf("detail = %q, want %q", got.Detail, ua)
	}
}

// DetectAppFromUA 用于历史数据回填：只认产品指纹，不做任何兜底。
func TestDetectAppFromUA(t *testing.T) {
	cases := []struct {
		ua       string
		wantKind string
	}{
		{"Mozilla/5.0 TraeCN/1.107.1 Chrome/142.0 Electron/39.2.7 Safari/537.36", ClientTrae},
		{"TraeClient/TTNet", ClientTrae},
		{"GitHubCopilotChat/0.22.0", ClientCopilot},
		{"claude-cli/1.0.60 (external, cli)", ClientClaudeCode},
		{"Mozilla/5.0 (Windows NT 10.0) Chrome/126.0 Safari/537.36", ""},
		{"hertz", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.ua, func(t *testing.T) {
			kind, evidence := DetectAppFromUA(tc.ua)
			if kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", kind, tc.wantKind)
			}
			if (kind == "") != (evidence == "") {
				t.Fatalf("kind 与 evidence 不一致：%q / %q", kind, evidence)
			}
		})
	}
}

// 浏览器行为头优先于 UA，防止 UA 被改写后仍被误判为脚本工具。
func TestDetectClientPriority(t *testing.T) {
	h := http.Header{
		"Sec-Fetch-Mode": []string{"cors"},
		"User-Agent":     []string{"curl/8.7.1"},
	}
	if got := DetectClient(h); got.Kind != ClientBrowserJS {
		t.Fatalf("kind = %s, want %s", got.Kind, ClientBrowserJS)
	}

	// stainless 优先于框架 UA 判断。
	h2 := http.Header{
		"X-Stainless-Lang": []string{"python"},
		"User-Agent":       []string{"langchain/0.2.0"},
	}
	if got := DetectClient(h2); got.Kind != ClientOpenAIPy {
		t.Fatalf("kind = %s, want %s", got.Kind, ClientOpenAIPy)
	}
}

// 客户端识别不应影响协议置信度：ClassifyRequest 单独调用时必须保持原语义。
func TestDetectClientDoesNotAffectConfidence(t *testing.T) {
	res := ClassifyRequest(RequestInput{
		Method: http.MethodPost, Host: "api.openai.com", Path: "/v1/chat/completions",
		Headers: http.Header{"Authorization": []string{"Bearer sk-demo"}, "User-Agent": []string{"curl/8.7.1"}},
		Body:    chatBody(), KnownHost: true,
	})
	if res.Classification.Confidence != ConfidenceConfirmed {
		t.Fatalf("confidence = %s, want %s", res.Classification.Confidence, ConfidenceConfirmed)
	}
	// 客户端指纹由管线（pipeline.Handle）负责填充，ClassifyRequest 保持职责单一。
	if res.Classification.ClientKind != "" {
		t.Fatalf("ClassifyRequest 不应填充 ClientKind，got %q", res.Classification.ClientKind)
	}
}
