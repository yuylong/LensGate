package openai

import (
	"net/http"
	"strings"
)

// 客户端指纹类别。这些值是控制台展示与日志检索的稳定标识，不要随意改动。
//
// 重要：这是基于请求头的“自声明指纹”推断，UA 等字段可被伪造，
// 且只能识别到 SDK/工具层，无法穿透到上层 Agent 产品名。
const (
	ClientBrowser    = "browser"           // 浏览器地址栏/链接直接访问（导航请求）
	ClientBrowserJS  = "browser-fetch"     // 浏览器页面内 JS（fetch/XHR）发起
	ClientOpenAIPy   = "openai-python-sdk" // OpenAI 官方 Python SDK
	ClientOpenAINode = "openai-node-sdk"   // OpenAI 官方 Node/TS SDK
	ClientSDKOther   = "openai-sdk"        // 其他语言的 OpenAI 官方 SDK（Go/Ruby/Java 等）
	ClientLangChain  = "langchain"         // LangChain 及其衍生框架
	ClientLlamaIdx   = "llamaindex"        // LlamaIndex
	ClientOpenRouter = "openrouter"        // OpenRouter 归因头（X-Title / HTTP-Referer）
	ClientCurl       = "curl"
	ClientPostman    = "postman"
	ClientPythonHTTP = "python-http" // python-requests / httpx / aiohttp
	ClientGoHTTP     = "go-http-client"
	ClientNodeHTTP   = "node-http" // undici / axios / node-fetch
	ClientPowerShell = "powershell"
	ClientHertz      = "hertz"    // CloudWeGo Hertz（字节系 Go HTTP 框架），常见于 Trae 等服务端
	ClientElectron   = "electron" // Electron 桌面应用（未声明具体产品时）
	ClientUnknown    = "unknown"
)

// 已知 AI 应用 / Agent 桌面端与 CLI。这些是产品级自声明指纹，
// 优先级高于通用 SDK 指纹（它们底层往往就是官方 SDK，只看 stainless 头会丢失应用信息）。
const (
	ClientTrae       = "trae"
	ClientCopilot    = "copilot"
	ClientClaudeCode = "claude-code"
	ClientCursor     = "cursor"
	ClientWindsurf   = "windsurf"
	ClientCline      = "cline"
	ClientContinue   = "continue"
	ClientAider      = "aider"
	ClientCodex      = "codex"
	ClientGeminiCLI  = "gemini-cli"
)

// appFingerprints 是产品级 UA 指纹表（子串匹配，均为小写）。
// 注意：只有产品在 User-Agent 中自报家门时才能命中；Electron 应用若只发
// Chromium UA 则无法区分到产品，只能识别为 electron。
var appFingerprints = []struct {
	kind     string
	contains []string
}{
	{ClientClaudeCode, []string{"claude-cli", "claude-code"}},
	{ClientCopilot, []string{"githubcopilot", "copilot-chat", "github-copilot"}},
	// Trae 的 UA 有多种形态：Trae/1.x、TraeCN/1.x（国内版）、TraeClient/TTNet（内嵌网络库）。
	{ClientTrae, []string{"trae/", "traecn", "traeclient", "trae cn"}},
	{ClientCursor, []string{"cursor/", "cursor-agent"}},
	{ClientWindsurf, []string{"windsurf", "codeium"}},
	{ClientCline, []string{"cline/"}},
	{ClientContinue, []string{"continue.dev", "continue/"}},
	{ClientAider, []string{"aider/"}},
	{ClientCodex, []string{"codex_cli", "codex-cli", "openai-codex"}},
	{ClientGeminiCLI, []string{"geminicli", "gemini-cli"}},
}

// ClientInfo 是客户端指纹识别结果。
type ClientInfo struct {
	Kind     string
	Detail   string   // 原始 User-Agent，便于人工复核
	Evidence []string // 命中的指纹依据，控制台“推断”说明用
}

// DetectAppFromUA 只做“产品级指纹”匹配，不做浏览器/SDK 兜底。
// 命中返回类别与依据，未命中返回空串。
// 单独暴露的用途：启动时回填历史流量（JSONL 里只留有 UA，没有完整头）。
func DetectAppFromUA(ua string) (kind, evidence string) {
	lua := strings.ToLower(strings.TrimSpace(ua))
	for _, fp := range appFingerprints {
		for _, sub := range fp.contains {
			if strings.Contains(lua, sub) {
				return fp.kind, "app: " + sub
			}
		}
	}
	return "", ""
}

// DetectClient 按优先级从请求头推断客户端类别。
//
// 优先级：
//  1. 已知 AI 应用/Agent 产品指纹（UA 自报家门，信息量最大，须先于通用 SDK 判断）
//  2. Electron 桌面应用（未声明产品时）
//  3. Sec-Fetch-* 浏览器行为头（最难伪造）
//  4. x-stainless-* 官方 SDK
//  5. 框架特征头
//  6. 归因头（X-Title / HTTP-Referer）
//  7. 其余 User-Agent 特征
//
// 全不命中时 Kind 为 unknown，Detail 仍保留原始 UA 供控制台直接展示。
func DetectClient(h http.Header) ClientInfo {
	info := ClientInfo{Kind: ClientUnknown}
	if h == nil {
		return info
	}
	ua := strings.TrimSpace(h.Get("User-Agent"))
	info.Detail = ua
	lua := strings.ToLower(ua)

	// 1) 已知 AI 应用/Agent：产品级自声明，优先于其底层 SDK。
	if kind, ev := DetectAppFromUA(ua); kind != "" {
		info.Kind = kind
		info.Evidence = []string{ev}
		return info
	}

	// 2) Electron 桌面应用（往往也带 Sec-Fetch-*，必须在浏览器判断之前）。
	if strings.Contains(lua, "electron/") {
		info.Kind = ClientElectron
		info.Evidence = []string{"ua: electron"}
		return info
	}

	// 3) 浏览器行为头：浏览器会自动附加，非浏览器客户端一般不会带。
	secFetchMode := strings.ToLower(strings.TrimSpace(h.Get("Sec-Fetch-Mode")))
	switch {
	case secFetchMode == "navigate" || h.Get("Sec-Fetch-User") != "":
		info.Kind = ClientBrowser
		info.Evidence = []string{"sec-fetch: navigate"}
		return info
	case secFetchMode != "":
		info.Kind = ClientBrowserJS
		info.Evidence = []string{"sec-fetch: " + secFetchMode}
		return info
	case h.Get("Sec-CH-UA") != "":
		info.Kind = ClientBrowserJS
		info.Evidence = []string{"sec-ch-ua"}
		return info
	}

	// 4) OpenAI 官方 SDK 的 stainless 指纹头。
	if lang := strings.ToLower(strings.TrimSpace(h.Get("X-Stainless-Lang"))); lang != "" {
		switch {
		case strings.Contains(lang, "python"):
			info.Kind = ClientOpenAIPy
		case lang == "js" || strings.Contains(lang, "node") || strings.Contains(lang, "typescript"):
			info.Kind = ClientOpenAINode
		default:
			info.Kind = ClientSDKOther
		}
		info.Evidence = []string{"x-stainless-lang: " + lang}
		return info
	}
	if hasHeaderPrefix(h, "x-stainless-") {
		info.Kind = ClientSDKOther
		info.Evidence = []string{"x-stainless-*"}
		return info
	}

	// 5) 上层 Agent 框架特征。必须在 UA 兜底之前判断：
	// 多数框架复用官方 SDK，UA 会带 openai/python，但框架会额外声明自己的头。
	if hasHeaderPrefix(h, "x-langchain") || hasHeaderPrefix(h, "x-langsmith") || strings.Contains(lua, "langchain") {
		info.Kind = ClientLangChain
		info.Evidence = []string{"framework: langchain"}
		return info
	}
	if strings.Contains(lua, "llamaindex") || strings.Contains(lua, "llama-index") || strings.Contains(lua, "llama_index") {
		info.Kind = ClientLlamaIdx
		info.Evidence = []string{"framework: llamaindex"}
		return info
	}

	// 6) 老版本官方 SDK 走 UA 声明。
	switch {
	case strings.Contains(lua, "openai/python") || strings.Contains(lua, "openai-python"):
		info.Kind = ClientOpenAIPy
		info.Evidence = []string{"ua: openai python sdk"}
		return info
	case strings.Contains(lua, "openai/node") || strings.Contains(lua, "openai-node"):
		info.Kind = ClientOpenAINode
		info.Evidence = []string{"ua: openai node sdk"}
		return info
	}

	// 7) OpenRouter 归因头：X-Title / HTTP-Referer 是 OpenRouter 推荐的客户端声明。
	if h.Get("X-Title") != "" || h.Get("HTTP-Referer") != "" {
		info.Kind = ClientOpenRouter
		info.Evidence = []string{"attribution: x-title/http-referer"}
		return info
	}

	// 8) 常见命令行/脚本工具，依据 User-Agent。
	switch {
	case strings.HasPrefix(lua, "curl/"):
		info.Kind = ClientCurl
		info.Evidence = []string{"ua: curl"}
	case strings.Contains(lua, "postmanruntime"):
		info.Kind = ClientPostman
		info.Evidence = []string{"ua: postman"}
	case strings.Contains(lua, "python-requests"), strings.Contains(lua, "python-httpx"),
		strings.Contains(lua, "python-urllib"), strings.Contains(lua, "aiohttp/"):
		info.Kind = ClientPythonHTTP
		info.Evidence = []string{"ua: python http client"}
	case strings.Contains(lua, "go-http-client"):
		info.Kind = ClientGoHTTP
		info.Evidence = []string{"ua: go-http-client"}
	case strings.HasPrefix(lua, "hertz"):
		// CloudWeGo Hertz：字节系 Go HTTP 框架，常见于 Trae 等服务端；本身不指向具体产品。
		info.Kind = ClientHertz
		info.Evidence = []string{"ua: hertz"}
	case strings.Contains(lua, "windowspowershell"), strings.Contains(lua, "powershell/"):
		info.Kind = ClientPowerShell
		info.Evidence = []string{"ua: powershell"}
	case strings.Contains(lua, "undici"), strings.Contains(lua, "axios/"),
		strings.Contains(lua, "node-fetch"), strings.HasPrefix(lua, "node/"):
		info.Kind = ClientNodeHTTP
		info.Evidence = []string{"ua: node http client"}
	case strings.Contains(lua, "mozilla/5.0"):
		// 浏览器剥离了 Sec-Fetch-* （如部分代理/隐私插件）时的兜底。
		info.Kind = ClientBrowser
		info.Evidence = []string{"ua: browser (no sec-fetch)"}
	}
	return info
}

func hasHeaderPrefix(h http.Header, prefix string) bool {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), prefix) {
			return true
		}
	}
	return false
}
