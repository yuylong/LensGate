package pipeline

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"lensgate/internal/detect"
	"lensgate/internal/model"
	"lensgate/internal/proto/openai"
)

// buildFlowDetail 把管线内存中的完整会话整理成对外展示的明细。
// 这里直接复用 openai.ParseRequest/ParseResponse 的结果，不在 API 层重复解析。
// 所有正文与头部都会脱敏，正文仍受 max_inspect_body 截断约束。
func buildFlowDetail(flow model.Flow, sess *model.Session, req *openai.ParsedRequest, resp *openai.ParsedResponse) model.FlowDetail {
	detail := model.FlowDetail{
		Flow:  flow,
		ALPN:  append([]string(nil), sess.Meta.ALPN...),
		IsTLS: sess.Meta.IsTLS,
		Request: model.RequestDetail{
			Method:        sess.Request.Method,
			Host:          sess.Request.Host,
			Path:          sess.Request.Path,
			Query:         sess.Request.Query,
			Headers:       redactHeaders(sess.Request.Headers),
			ContentType:   sess.Request.ContentType,
			Body:          redactJSONBody(sess.Request.Body),
			BodyTruncated: sess.Request.BodyTruncated,
		},
		Response: model.ResponseDetail{
			Status:        sess.Response.Status,
			Headers:       redactHeaders(sess.Response.Headers),
			ContentType:   sess.Response.ContentType,
			Body:          redactJSONBody(sess.Response.Body),
			BodyTruncated: sess.Response.BodyTruncated,
			Chunks:        sess.Response.Chunks,
			Completed:     sess.Response.Completed,
			Error:         detect.Redact(sess.Response.Error),
		},
	}

	if req != nil {
		detail.Request.Model = req.Model
		detail.Request.Stream = req.Stream
		detail.Request.Instructions = detect.Redact(req.Instructions)
		detail.Request.Input = detect.Redact(req.Input)
		for _, m := range req.Messages {
			md := model.MessageDetail{Role: m.Role, Content: detect.Redact(m.Content)}
			for _, tc := range m.ToolCalls {
				md.ToolCalls = append(md.ToolCalls, model.ToolCallDetail{
					ID:        tc.ID,
					Name:      tc.Name,
					Arguments: detect.Redact(tc.Arguments),
				})
			}
			detail.Request.Messages = append(detail.Request.Messages, md)
		}
		for _, t := range req.Tools {
			detail.Request.Tools = append(detail.Request.Tools, model.ToolDetail{
				Name:        t.Name,
				Description: detect.Redact(t.Description),
			})
		}
	}

	if resp != nil {
		detail.Response.Text = detect.Redact(resp.Text)
		detail.Response.FinishReason = resp.FinishReason
		detail.Response.Object = resp.Object
		for _, tc := range resp.ToolCalls {
			detail.Response.ToolCalls = append(detail.Response.ToolCalls, model.ToolCallDetail{
				ID:        tc.ID,
				Name:      tc.Name,
				Arguments: detect.Redact(tc.Arguments),
			})
		}
	}

	if len(sess.Response.SSE) > 0 {
		detail.Response.SSE = make([]model.SSEDetail, 0, len(sess.Response.SSE))
		for _, ev := range sess.Response.SSE {
			detail.Response.SSE = append(detail.Response.SSE, model.SSEDetail{
				Event: ev.Event,
				Data:  redactJSONText(ev.Data),
			})
		}
	}
	return detail
}

// sensitiveHeaderKeys 命中任意子串即视为敏感头，整体打码而不是逐字符脱敏。
var sensitiveHeaderKeys = []string{
	"authorization", "api-key", "api_key", "apikey", "token",
	"secret", "password", "cookie", "credential",
}

func redactHeaders(h http.Header) []model.Header {
	if len(h) == 0 {
		return nil
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]model.Header, 0, len(names))
	for _, name := range names {
		values := make([]string, 0, len(h[name]))
		for _, v := range h[name] {
			values = append(values, redactHeaderValue(name, v))
		}
		out = append(out, model.Header{Name: name, Values: values})
	}
	return out
}

func isSensitiveHeader(name string) bool {
	n := strings.ToLower(name)
	for _, key := range sensitiveHeaderKeys {
		if strings.Contains(n, key) {
			return true
		}
	}
	return false
}

// redactHeaderValue 对敏感头保留认证方案（如 Bearer），其余值整体打码；
// 非敏感头交给通用脱敏规则，避免 UA 等字段里夹带的凭据泄露。
func redactHeaderValue(name, value string) string {
	if isSensitiveHeader(name) {
		v := strings.TrimSpace(value)
		if v == "" {
			return ""
		}
		if parts := strings.SplitN(v, " ", 2); len(parts) == 2 && len(parts[0]) <= 16 && !strings.ContainsAny(parts[0], "=;,:") {
			return parts[0] + " ***"
		}
		return "***"
	}
	return detect.Redact(value)
}

// redactJSONBody 对 JSON 正文按字符串值逐项脱敏，保证格式化后仍是合法 JSON；
// 非 JSON（SSE 流、截断的正文等）退化为整体文本脱敏。
func redactJSONBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return detect.Redact(string(body))
	}
	out, err := json.MarshalIndent(redactJSONValue(v), "", "  ")
	if err != nil {
		return detect.Redact(string(body))
	}
	return string(out)
}

// redactJSONText 与 redactJSONBody 相同，但保持紧凑格式，适合单条 SSE data。
func redactJSONText(s string) string {
	if s == "" {
		return ""
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return detect.Redact(s)
	}
	out, err := json.Marshal(redactJSONValue(v))
	if err != nil {
		return detect.Redact(s)
	}
	return string(out)
}

func redactJSONValue(v any) any {
	switch t := v.(type) {
	case string:
		return detect.Redact(t)
	case []any:
		for i := range t {
			t[i] = redactJSONValue(t[i])
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = redactJSONValue(t[k])
		}
		return t
	}
	return v
}
