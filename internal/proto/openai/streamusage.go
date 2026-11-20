package openai

import "encoding/json"

// InjectStreamUsage 在流式 chat completions 请求体中注入 stream_options.include_usage=true。
// 真实上游默认不在 SSE 流末尾返回 usage（Token 统计为空的根因），注入后上游会附带 usage chunk，
// 现有 parser 无需改动即可识别。仅当 stream=true 且请求未携带 stream_options 时注入；
// 其余情况（非流式、已显式设置、JSON 无法解析）原样返回，ok=false。
func InjectStreamUsage(body []byte) ([]byte, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, false
	}
	var stream bool
	if v, ok := raw["stream"]; !ok || json.Unmarshal(v, &stream) != nil || !stream {
		return body, false
	}
	if _, ok := raw["stream_options"]; ok {
		return body, false
	}
	raw["stream_options"] = json.RawMessage(`{"include_usage":true}`)
	out, err := json.Marshal(raw)
	if err != nil {
		return body, false
	}
	return out, true
}
