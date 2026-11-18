package openai

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"lensgate/internal/model"
)

// 置信度等级。判别顺序：confirmed > compatible > suspected > not_ai。
const (
	ConfidenceConfirmed  = "confirmed"
	ConfidenceCompatible = "compatible"
	ConfidenceSuspected  = "suspected"
	ConfidenceNotAI      = "not_ai"
)

const (
	VariantChat       = "chat.completions"
	VariantResponses  = "responses"
	VariantEmbeddings = "embeddings"
)

var (
	reChat           = regexp.MustCompile(`(?i)(^|/)(v1|api/v1)/chat/completions/?$`)
	reAzureChat      = regexp.MustCompile(`(?i)(^|/)openai/deployments/[^/]+/chat/completions/?$`)
	reResponses      = regexp.MustCompile(`(?i)(^|/)(v1|api/v1)/responses/?$`)
	reAzureResponses = regexp.MustCompile(`(?i)(^|/)openai/responses/?$`)
	reEmbeddings     = regexp.MustCompile(`(?i)(^|/)(v1|api/v1)/embeddings/?$`)
	reAzureEmbedding = regexp.MustCompile(`(?i)(^|/)openai/deployments/[^/]+/embeddings/?$`)
)

// RequestInput 是识别所需的全部请求侧信号。
type RequestInput struct {
	Method    string
	Host      string
	Path      string
	Headers   http.Header
	Body      []byte
	KnownHost bool
}

// RequestResult 携带识别结论和解析结果，供后续检测复用。
type RequestResult struct {
	Classification model.Classification
	Parsed         *ParsedRequest
	PathMatched    bool
	HeaderSignal   bool
}

// MatchPathVariant 只看路径形态，返回 API 变体；Azure 部署路径也算匹配。
func MatchPathVariant(path string) (string, bool) {
	p := path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	switch {
	case reAzureChat.MatchString(p):
		return VariantChat, true
	case reAzureEmbedding.MatchString(p):
		return VariantEmbeddings, true
	case reAzureResponses.MatchString(p):
		return VariantResponses, true
	case reChat.MatchString(p):
		return VariantChat, true
	case reResponses.MatchString(p):
		return VariantResponses, true
	case reEmbeddings.MatchString(p):
		return VariantEmbeddings, true
	}
	return "", false
}

// ClassifyRequest 用路径 + JSON schema + 认证/SDK 头 + 已知域名综合判定。
// 关键点：域名只是其中一个弱信号，不能单独决定“这是 OpenAI 流量”。
func ClassifyRequest(in RequestInput) RequestResult {
	res := RequestResult{}
	res.Classification.ProtocolFamily = "unknown"

	variant, pathMatched := MatchPathVariant(in.Path)
	res.PathMatched = pathMatched

	var parsed *ParsedRequest
	if len(in.Body) > 0 {
		if pr, err := ParseRequest(in.Body); err == nil {
			parsed = pr
			res.Parsed = pr
		}
	}
	schemaOK := parsed != nil && schemaMatches(variant, parsed)

	headerEvidence := headerSignals(in.Headers)
	res.HeaderSignal = len(headerEvidence) > 0

	evidence := make([]string, 0, 6)
	if pathMatched {
		evidence = append(evidence, "path:"+variant)
	}
	if schemaOK {
		evidence = append(evidence, "schema:"+schemaHint(variant))
	}
	evidence = append(evidence, headerEvidence...)
	if in.KnownHost {
		evidence = append(evidence, "host:known")
	} else {
		evidence = append(evidence, "host:unknown")
	}

	switch {
	case pathMatched && schemaOK && (res.HeaderSignal || in.KnownHost):
		res.Classification.Confidence = ConfidenceConfirmed
		res.Classification.Reason = "路径、报文结构与认证特征同时匹配 OpenAI 协议"
	case pathMatched && schemaOK:
		res.Classification.Confidence = ConfidenceCompatible
		res.Classification.Reason = "路径与报文结构匹配 OpenAI 协议，但缺少认证或已知域名佐证"
	case pathMatched && res.HeaderSignal:
		res.Classification.Confidence = ConfidenceSuspected
		res.Classification.Reason = "路径符合 OpenAI API 形态，报文结构未能确认"
	case pathMatched:
		res.Classification.Confidence = ConfidenceSuspected
		res.Classification.Reason = "仅路径符合 OpenAI API 形态"
	case schemaOK:
		res.Classification.Confidence = ConfidenceSuspected
		res.Classification.Reason = "报文结构疑似 OpenAI 协议，但路径不符"
	default:
		res.Classification.Confidence = ConfidenceNotAI
		res.Classification.Reason = "未发现 OpenAI 协议特征"
	}

	if pathMatched {
		res.Classification.ProtocolFamily = "openai"
		res.Classification.APIVariant = variant
	} else if schemaOK {
		res.Classification.ProtocolFamily = "openai-compatible"
	}
	res.Classification.Evidence = evidence
	return res
}

// RefineWithResponse 用响应侧强特征修正请求侧结论。
// 典型场景：未知域名 + 非标准路径，只能靠响应 object/SSE 事件确认。
func RefineWithResponse(c model.Classification, resp *ParsedResponse, pathMatched, headerSignal, knownHost bool) model.Classification {
	if resp == nil || !resp.Strong {
		return c
	}
	c.Evidence = append(c.Evidence, "response:"+resp.StrongReason)
	if c.ProtocolFamily == "unknown" {
		c.ProtocolFamily = "openai-compatible"
	}
	if resp.Object != "" && c.APIVariant == "" {
		switch strings.ToLower(resp.Object) {
		case "chat.completion", "chat.completion.chunk":
			c.APIVariant = VariantChat
		case "response":
			c.APIVariant = VariantResponses
		case "list":
			c.APIVariant = VariantEmbeddings
		}
	}

	switch {
	case c.Confidence == ConfidenceConfirmed:
		return c
	case pathMatched && (headerSignal || knownHost):
		c.Confidence = ConfidenceConfirmed
		c.Reason = "请求侧已匹配，响应结构进一步确认 OpenAI 协议"
	case pathMatched:
		c.Confidence = ConfidenceCompatible
		c.Reason = "路径与响应结构均符合 OpenAI 协议"
	case headerSignal || knownHost:
		c.Confidence = ConfidenceCompatible
		c.Reason = "域名或认证特征可信，响应结构符合 OpenAI 协议"
	default:
		c.Confidence = ConfidenceSuspected
		c.Reason = "仅响应结构符合 OpenAI 协议，来源不可信"
	}
	return c
}

func schemaMatches(variant string, pr *ParsedRequest) bool {
	if pr == nil || pr.Raw == nil {
		return false
	}
	switch variant {
	case VariantChat:
		return hasRaw(pr.Raw, "messages")
	case VariantResponses:
		return hasRaw(pr.Raw, "input") || hasRaw(pr.Raw, "instructions")
	case VariantEmbeddings:
		return hasRaw(pr.Raw, "input")
	}
	// 路径不匹配时，任何 OpenAI 形态的字段都算弱 schema 命中。
	return hasRaw(pr.Raw, "messages") || (hasRaw(pr.Raw, "input") && hasRaw(pr.Raw, "model"))
}

func schemaHint(variant string) string {
	switch variant {
	case VariantChat:
		return "messages"
	case VariantResponses:
		return "input/instructions"
	case VariantEmbeddings:
		return "input"
	}
	return "generic"
}

func hasRaw(raw map[string]json.RawMessage, key string) bool {
	_, ok := raw[key]
	return ok
}

func headerSignals(h http.Header) []string {
	if h == nil {
		return nil
	}
	var ev []string
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(h.Get("Authorization"))), "bearer ") {
		ev = append(ev, "auth:bearer")
	}
	if h.Get("api-key") != "" {
		ev = append(ev, "auth:api-key")
	}
	if h.Get("OpenAI-Beta") != "" || h.Get("openai-organization") != "" {
		ev = append(ev, "header:openai")
	}
	ua := strings.ToLower(h.Get("User-Agent"))
	if strings.Contains(ua, "openai") || strings.Contains(ua, "langchain") || strings.Contains(ua, "llamaindex") {
		ev = append(ev, "ua:openai-sdk")
	}
	for k := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-stainless-") {
			ev = append(ev, "sdk:stainless")
			break
		}
	}
	if h.Get("X-Title") != "" || h.Get("HTTP-Referer") != "" {
		ev = append(ev, "client:attribution")
	}
	return ev
}
