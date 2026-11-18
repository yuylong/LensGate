package openai

import (
	"bytes"
	"strings"

	"lensgate/internal/model"
)

// SSEParser 按行增量解析 Server-Sent Events，适合边转发边聚合。
type SSEParser struct {
	buf   []byte
	event string
	data  []string
}

func (p *SSEParser) Feed(chunk []byte) []model.SSEEvent {
	p.buf = append(p.buf, chunk...)
	var out []model.SSEEvent
	for {
		i := bytes.IndexByte(p.buf, '\n')
		if i < 0 {
			break
		}
		line := string(p.buf[:i])
		p.buf = p.buf[i+1:]
		line = strings.TrimSuffix(line, "\r")

		if line == "" {
			if len(p.data) > 0 {
				out = append(out, model.SSEEvent{Event: p.event, Data: strings.Join(p.data, "\n")})
			}
			p.event = ""
			p.data = nil
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			field = line
			value = ""
		}
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			p.event = value
		case "data":
			p.data = append(p.data, value)
		}
	}
	return out
}

func (p *SSEParser) Close() []model.SSEEvent {
	if len(p.data) == 0 {
		return nil
	}
	ev := model.SSEEvent{Event: p.event, Data: strings.Join(p.data, "\n")}
	p.event = ""
	p.data = nil
	return []model.SSEEvent{ev}
}

func ParseSSEBytes(b []byte) []model.SSEEvent {
	p := &SSEParser{}
	out := p.Feed(b)
	return append(out, p.Close()...)
}
