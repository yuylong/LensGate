package openai

import (
	"strings"
	"testing"

	"lensgate/internal/model"
)

func TestParseRequestChat(t *testing.T) {
	pr, err := ParseRequest([]byte(`{
		"model":"gpt-4o-mini","stream":true,
		"messages":[
			{"role":"system","content":[{"type":"text","text":"你是助手"}]},
			{"role":"user","content":"请总结"}
		],
		"tools":[{"type":"function","function":{"name":"shell_exec","description":"执行命令"}}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if pr.Model != "gpt-4o-mini" || !pr.Stream {
		t.Fatalf("unexpected model/stream: %+v", pr)
	}
	if len(pr.Messages) != 2 || pr.Messages[0].Content != "你是助手" {
		t.Fatalf("messages parsed wrong: %+v", pr.Messages)
	}
	if len(pr.Tools) != 1 || pr.Tools[0].Name != "shell_exec" {
		t.Fatalf("tools parsed wrong: %+v", pr.Tools)
	}
}

func TestParseSSEAggregation(t *testing.T) {
	events := []model.SSEEvent{
		{Data: `{"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"delta":{"content":"Hello "}}]}`},
		{Data: `{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"delta":{"content":"world"},"finish_reason":"stop"}]}`},
		{Data: `{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`},
		{Data: `[DONE]`},
	}
	pr, err := ParseResponse(model.ResponseInfo{ContentType: "text/event-stream", SSE: events})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Text != "Hello world" {
		t.Fatalf("text = %q", pr.Text)
	}
	if pr.FinishReason != "stop" {
		t.Fatalf("finish = %q", pr.FinishReason)
	}
	if pr.Usage == nil || pr.Usage.Total != 15 || pr.Usage.Input != 10 || pr.Usage.Output != 5 {
		t.Fatalf("usage = %+v", pr.Usage)
	}
	if !pr.Strong || !strings.Contains(pr.StrongReason, "chat.completion") {
		t.Fatalf("strong = %v reason = %s", pr.Strong, pr.StrongReason)
	}
}

func TestParseResponseToolCall(t *testing.T) {
	events := []model.SSEEvent{
		{Data: `{"object":"chat.completion.chunk","choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"shell_exec","arguments":"{\"command\":\"ls\"}"}}]}}]}`},
	}
	pr, err := ParseResponse(model.ResponseInfo{ContentType: "text/event-stream", SSE: events})
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.ToolCalls) != 1 || pr.ToolCalls[0].Name != "shell_exec" {
		t.Fatalf("tool calls = %+v", pr.ToolCalls)
	}
	if pr.ToolCalls[0].Arguments != `{"command":"ls"}` {
		t.Fatalf("arguments = %q", pr.ToolCalls[0].Arguments)
	}
}

func TestParseResponseResponsesObject(t *testing.T) {
	body := []byte(`{"id":"resp_1","object":"response","model":"gpt-4o-mini","output":[{"type":"message","content":[{"type":"output_text","text":"hi there"}]}],"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}`)
	pr, err := ParseResponse(model.ResponseInfo{ContentType: "application/json", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Text != "hi there" || pr.Object != "response" {
		t.Fatalf("parsed = %+v", pr)
	}
	if pr.Usage == nil || pr.Usage.Total != 5 {
		t.Fatalf("usage = %+v", pr.Usage)
	}
	if !pr.Strong || pr.StrongReason != "output" {
		t.Fatalf("strong = %v reason = %s", pr.Strong, pr.StrongReason)
	}
}

func TestParseSSEResponsesNoDuplicateText(t *testing.T) {
	events := []model.SSEEvent{
		{Event: "response.output_text.delta", Data: `{"type":"response.output_text.delta","delta":"hello"}`},
		{Event: "response.completed", Data: `{"type":"response.completed","response":{"model":"gpt-4o-mini","output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}],"usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}}`},
	}
	pr, err := ParseResponse(model.ResponseInfo{ContentType: "text/event-stream", SSE: events})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Text != "hello" {
		t.Fatalf("text duplicated: %q", pr.Text)
	}
	if pr.Usage == nil || pr.Usage.Total != 3 {
		t.Fatalf("usage = %+v", pr.Usage)
	}
}

func TestSSEParserIncrementalMultiline(t *testing.T) {
	input := "event: message\r\ndata: line1\r\ndata: line2\r\n\r\ndata: [DONE]\n\n"
	p := &SSEParser{}
	var got []model.SSEEvent
	for i := 0; i < len(input); i += 3 {
		end := i + 3
		if end > len(input) {
			end = len(input)
		}
		got = append(got, p.Feed([]byte(input[i:end]))...)
	}
	got = append(got, p.Close()...)
	if len(got) != 2 {
		t.Fatalf("events = %+v", got)
	}
	if got[0].Event != "message" || got[0].Data != "line1\nline2" {
		t.Fatalf("first event = %+v", got[0])
	}
	if got[1].Data != "[DONE]" {
		t.Fatalf("second event = %+v", got[1])
	}
}
