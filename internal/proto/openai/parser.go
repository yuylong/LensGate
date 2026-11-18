package openai

import (
	"encoding/json"
	"errors"
	"strings"

	"lensgate/internal/model"
)

var errEmptyBody = errors.New("empty body")

type Message struct {
	Role      string
	Content   string
	ToolCalls []ToolCall
}

type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

type ToolDef struct {
	Name        string
	Description string
}

type ParsedRequest struct {
	Model        string
	Stream       bool
	Messages     []Message
	Instructions string
	Input        string
	Tools        []ToolDef
	Raw          map[string]json.RawMessage
}

type ParsedResponse struct {
	Object       string
	ID           string
	Model        string
	Text         string
	FinishReason string
	ToolCalls    []ToolCall
	Usage        *model.Usage
	Events       int
	Strong       bool
	StrongReason string
}

type usageJSON struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
}

func (u *usageJSON) toUsage() *model.Usage {
	if u == nil {
		return nil
	}
	in := u.PromptTokens
	if in == 0 {
		in = u.InputTokens
	}
	out := u.CompletionTokens
	if out == 0 {
		out = u.OutputTokens
	}
	total := u.TotalTokens
	if total == 0 {
		total = in + out
	}
	if in == 0 && out == 0 && total == 0 {
		return nil
	}
	return &model.Usage{Input: in, Output: out, Total: total}
}

func ParseRequest(body []byte) (*ParsedRequest, error) {
	if len(body) == 0 {
		return nil, errEmptyBody
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	pr := &ParsedRequest{Raw: raw}
	if v, ok := raw["model"]; ok {
		_ = json.Unmarshal(v, &pr.Model)
	}
	if v, ok := raw["stream"]; ok {
		_ = json.Unmarshal(v, &pr.Stream)
	}
	if v, ok := raw["instructions"]; ok {
		_ = json.Unmarshal(v, &pr.Instructions)
	}
	if v, ok := raw["input"]; ok {
		pr.Input = extractText(v)
	}
	if v, ok := raw["messages"]; ok {
		pr.Messages = parseMessages(v)
	}
	if v, ok := raw["tools"]; ok {
		pr.Tools = parseTools(v)
	}
	return pr, nil
}

func parseMessages(raw json.RawMessage) []Message {
	var arr []map[string]json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return nil
	}
	out := make([]Message, 0, len(arr))
	for _, item := range arr {
		m := Message{}
		if v, ok := item["role"]; ok {
			_ = json.Unmarshal(v, &m.Role)
		}
		if v, ok := item["content"]; ok {
			m.Content = extractText(v)
		}
		if v, ok := item["tool_calls"]; ok {
			m.ToolCalls = parseToolCalls(v)
		}
		out = append(out, m)
	}
	return out
}

func parseToolCalls(raw json.RawMessage) []ToolCall {
	var arr []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
		Function  struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &arr) != nil {
		return nil
	}
	out := make([]ToolCall, 0, len(arr))
	for _, item := range arr {
		tc := ToolCall{ID: item.ID, Name: item.Name, Arguments: item.Arguments}
		if item.Function.Name != "" {
			tc.Name = item.Function.Name
		}
		if item.Function.Arguments != "" {
			tc.Arguments = item.Function.Arguments
		}
		out = append(out, tc)
	}
	return out
}

func parseTools(raw json.RawMessage) []ToolDef {
	var arr []map[string]json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return nil
	}
	out := make([]ToolDef, 0, len(arr))
	for _, item := range arr {
		td := ToolDef{}
		if fn, ok := item["function"]; ok {
			var f struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			}
			_ = json.Unmarshal(fn, &f)
			td.Name = f.Name
			td.Description = f.Description
		}
		if td.Name == "" {
			if v, ok := item["name"]; ok {
				_ = json.Unmarshal(v, &td.Name)
			}
		}
		if td.Description == "" {
			if v, ok := item["description"]; ok {
				_ = json.Unmarshal(v, &td.Description)
			}
		}
		out = append(out, td)
	}
	return out
}

// extractText 处理字符串、多模态数组和嵌套对象中的文本，图片/音频只保留占位。
func extractText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) == nil {
		var sb strings.Builder
		for _, part := range parts {
			if v, ok := part["text"]; ok {
				sb.WriteString(extractText(v))
				sb.WriteString(" ")
			}
			if v, ok := part["input_text"]; ok {
				sb.WriteString(extractText(v))
				sb.WriteString(" ")
			}
			if v, ok := part["output_text"]; ok {
				sb.WriteString(extractText(v))
				sb.WriteString(" ")
			}
			if v, ok := part["content"]; ok {
				sb.WriteString(extractText(v))
				sb.WriteString(" ")
			}
			if v, ok := part["type"]; ok {
				var t string
				_ = json.Unmarshal(v, &t)
				switch t {
				case "image_url", "input_image":
					sb.WriteString("[image] ")
				case "input_audio", "audio":
					sb.WriteString("[audio] ")
				}
			}
		}
		return strings.TrimSpace(sb.String())
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		for _, key := range []string{"text", "input_text", "output_text", "content"} {
			if v, ok := obj[key]; ok {
				if text := extractText(v); text != "" {
					return text
				}
			}
		}
	}
	return ""
}

func ParseResponse(info model.ResponseInfo) (*ParsedResponse, error) {
	pr := &ParsedResponse{}
	if len(info.SSE) > 0 || strings.Contains(strings.ToLower(info.ContentType), "text/event-stream") {
		pr.Events = len(info.SSE)
		pr.parseSSE(info.SSE)
		return pr, nil
	}
	if len(info.Body) == 0 {
		return pr, nil
	}

	var probe struct {
		Object  string `json:"object"`
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role      string          `json:"role"`
				Content   json.RawMessage `json:"content"`
				ToolCalls json.RawMessage `json:"tool_calls"`
			} `json:"message"`
			Delta struct {
				Content   json.RawMessage `json:"content"`
				ToolCalls json.RawMessage `json:"tool_calls"`
			} `json:"delta"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage  *usageJSON        `json:"usage"`
		Output []json.RawMessage `json:"output"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(info.Body, &probe); err != nil {
		return nil, err
	}

	pr.Object = probe.Object
	pr.ID = probe.ID
	pr.Model = probe.Model
	pr.Usage = probe.Usage.toUsage()

	if len(probe.Choices) > 0 {
		var sb strings.Builder
		for _, ch := range probe.Choices {
			if len(ch.Message.Content) > 0 {
				sb.WriteString(extractText(ch.Message.Content))
			}
			if len(ch.Delta.Content) > 0 {
				sb.WriteString(extractText(ch.Delta.Content))
			}
			if ch.FinishReason != "" {
				pr.FinishReason = ch.FinishReason
			}
			if len(ch.Message.ToolCalls) > 0 {
				pr.ToolCalls = append(pr.ToolCalls, parseToolCalls(ch.Message.ToolCalls)...)
			}
			if len(ch.Delta.ToolCalls) > 0 {
				pr.ToolCalls = append(pr.ToolCalls, parseToolCalls(ch.Delta.ToolCalls)...)
			}
		}
		pr.Text = sb.String()
		pr.Strong = true
		pr.StrongReason = "choices"
	}

	if len(probe.Output) > 0 {
		pr.Text += parseOutputItems(probe.Output, &pr.ToolCalls)
		pr.Strong = true
		pr.StrongReason = "output"
	}

	if isStrongObject(pr.Object) {
		pr.Strong = true
		if pr.StrongReason == "" {
			pr.StrongReason = "object:" + pr.Object
		}
	}

	if len(probe.Data) > 0 && strings.EqualFold(pr.Object, "list") && pr.Usage != nil && pr.Model != "" {
		pr.Strong = true
		pr.StrongReason = "embedding_usage"
	}

	return pr, nil
}

func (pr *ParsedResponse) parseSSE(events []model.SSEEvent) {
	var sb strings.Builder
	var completedText string
	toolByIndex := map[int]*ToolCall{}

	for _, ev := range events {
		data := strings.TrimSpace(ev.Data)
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			pr.Strong = true
			if pr.StrongReason == "" {
				pr.StrongReason = "[DONE]"
			}
			continue
		}

		var probe struct {
			Object   string          `json:"object"`
			ID       string          `json:"id"`
			Model    string          `json:"model"`
			Type     string          `json:"type"`
			Delta    json.RawMessage `json:"delta"`
			Item     json.RawMessage `json:"item"`
			Response json.RawMessage `json:"response"`
			Choices  []struct {
				Delta struct {
					Content   json.RawMessage `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *usageJSON `json:"usage"`
		}
		if json.Unmarshal([]byte(data), &probe) != nil {
			continue
		}

		if probe.Object != "" {
			pr.Object = probe.Object
		}
		if probe.ID != "" {
			pr.ID = probe.ID
		}
		if probe.Model != "" {
			pr.Model = probe.Model
		}
		if probe.Usage != nil {
			pr.Usage = probe.Usage.toUsage()
		}
		if isStrongObject(probe.Object) {
			pr.Strong = true
			pr.StrongReason = "object:" + probe.Object
		}

		for _, ch := range probe.Choices {
			if len(ch.Delta.Content) > 0 {
				sb.WriteString(extractText(ch.Delta.Content))
			}
			if ch.FinishReason != "" {
				pr.FinishReason = ch.FinishReason
			}
			for _, tc := range ch.Delta.ToolCalls {
				cur := toolByIndex[tc.Index]
				if cur == nil {
					cur = &ToolCall{}
					toolByIndex[tc.Index] = cur
				}
				if tc.ID != "" {
					cur.ID = tc.ID
				}
				if tc.Function.Name != "" {
					cur.Name = tc.Function.Name
				}
				if tc.Function.Arguments != "" {
					cur.Arguments += tc.Function.Arguments
				}
			}
		}

		switch probe.Type {
		case "response.created":
			var r struct {
				Model string `json:"model"`
			}
			_ = json.Unmarshal(probe.Response, &r)
			if r.Model != "" {
				pr.Model = r.Model
			}
			pr.Strong = true
			pr.StrongReason = "event:" + probe.Type
		case "response.output_text.delta":
			var d string
			_ = json.Unmarshal(probe.Delta, &d)
			if d != "" {
				sb.WriteString(d)
			}
			pr.Strong = true
			pr.StrongReason = "event:" + probe.Type
		case "response.completed":
			var r struct {
				Model  string            `json:"model"`
				Output []json.RawMessage `json:"output"`
				Usage  *usageJSON        `json:"usage"`
			}
			_ = json.Unmarshal(probe.Response, &r)
			if r.Model != "" {
				pr.Model = r.Model
			}
			if r.Usage != nil {
				pr.Usage = r.Usage.toUsage()
			}
			completedText += parseOutputItems(r.Output, &pr.ToolCalls)
			pr.Strong = true
			pr.StrongReason = "event:" + probe.Type
		case "response.output_item.added":
			var item struct {
				Item struct {
					Type      string `json:"type"`
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"item"`
			}
			_ = json.Unmarshal(probe.Item, &item.Item)
			if item.Item.Type == "function_call" && item.Item.Name != "" {
				pr.ToolCalls = append(pr.ToolCalls, ToolCall{Name: item.Item.Name, Arguments: item.Item.Arguments})
			}
		}
	}

	// 增量文本优先；只有在没有 delta 时才使用 completed 事件里的完整输出，避免重复。
	if sb.Len() == 0 && completedText != "" {
		pr.Text = completedText
	}
	pr.Text += sb.String()
	if len(toolByIndex) > 0 {
		for i := 0; i < len(toolByIndex); i++ {
			if tc := toolByIndex[i]; tc != nil {
				pr.ToolCalls = append(pr.ToolCalls, *tc)
			}
		}
	}
}

func parseOutputItems(items []json.RawMessage, calls *[]ToolCall) string {
	var sb strings.Builder
	for _, raw := range items {
		var item struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		for _, c := range item.Content {
			if c.Text != "" {
				sb.WriteString(c.Text)
			}
		}
		if item.Type == "function_call" && item.Name != "" {
			*calls = append(*calls, ToolCall{Name: item.Name, Arguments: item.Arguments})
		}
	}
	return sb.String()
}

func isStrongObject(obj string) bool {
	switch strings.ToLower(obj) {
	case "chat.completion", "chat.completion.chunk", "response":
		return true
	}
	return false
}
