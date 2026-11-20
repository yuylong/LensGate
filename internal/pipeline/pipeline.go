package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"lensgate/internal/config"
	"lensgate/internal/detect"
	"lensgate/internal/model"
	"lensgate/internal/proto/openai"
	"lensgate/internal/store"
)

const (
	maxSSEEvents = 5000
	summaryRunes = 240
)

// Pipeline 是接入层之上的全部业务逻辑：识别、检测、转发、记录。
// 它只依赖 HTTP 请求/响应，因此显式代理和透明代理可以共用。
type Pipeline struct {
	cfg       config.Config
	store     *store.Store
	detector  *detect.Detector
	transport *http.Transport
	logger    *log.Logger
	startedAt time.Time

	mu    sync.Mutex
	flows int64
}

func New(cfg config.Config, st *store.Store, det *detect.Detector, logger *log.Logger) *Pipeline {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     newUpstreamTLSConfig(cfg),
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Pipeline{
		cfg:       cfg,
		store:     st,
		detector:  det,
		transport: tr,
		logger:    logger,
		startedAt: time.Now(),
	}
}

func (p *Pipeline) StartedAt() time.Time { return p.startedAt }

func (p *Pipeline) Close() {
	p.transport.CloseIdleConnections()
}

// Handle 是 ingress.Handler 的实现。
func (p *Pipeline) Handle(ctx context.Context, meta model.ConnMeta, w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	sess := &model.Session{
		ID:        newID(),
		Meta:      meta,
		StartedAt: started,
	}

	body, truncated, tail := readRequestBody(r.Body, p.cfg.MaxRequestBytes)
	inspectBody := body
	if int64(len(inspectBody)) > int64(p.cfg.MaxInspectBody) {
		inspectBody = inspectBody[:p.cfg.MaxInspectBody]
	}

	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	host := hostOnly(r.Host)
	if host == "" {
		host = hostOnly(r.URL.Host)
	}
	knownHost := p.cfg.IsKnownHost(host)

	sess.Request = model.RequestInfo{
		Method:        r.Method,
		Host:          host,
		Path:          path,
		Query:         r.URL.RawQuery,
		Headers:       r.Header.Clone(),
		ContentType:   r.Header.Get("Content-Type"),
		Body:          inspectBody,
		BodyTruncated: truncated || len(inspectBody) < len(body),
	}

	reqResult := openai.ClassifyRequest(openai.RequestInput{
		Method:    r.Method,
		Host:      host,
		Path:      path,
		Headers:   r.Header,
		Body:      inspectBody,
		KnownHost: knownHost,
	})
	sess.Classification = reqResult.Classification

	// 客户端指纹：独立于协议置信度，仅用于回答“流量来自哪个客户端”。
	clientInfo := openai.DetectClient(r.Header)
	sess.Classification.ClientKind = clientInfo.Kind
	sess.Classification.ClientDetail = clientInfo.Detail
	sess.Classification.ClientReason = strings.Join(clientInfo.Evidence, " · ")
	if len(clientInfo.Evidence) > 0 {
		sess.ParseStatus = append(sess.ParseStatus, "client_fingerprint")
	}

	if reqResult.Parsed != nil {
		sess.Model = reqResult.Parsed.Model
		sess.Stream = reqResult.Parsed.Stream
		sess.ParseStatus = append(sess.ParseStatus, "request_parsed")
	} else if len(inspectBody) > 0 {
		sess.ParseStatus = append(sess.ParseStatus, "request_parse_failed")
	}
	if sess.Request.BodyTruncated {
		sess.ParseStatus = append(sess.ParseStatus, "request_truncated")
	}

	// 真实上游的流式响应默认不带 usage（Token 列为空的根因）：转发前对 chat
	// completions 流式请求注入 stream_options.include_usage，使上游在流末尾
	// 附带 usage chunk。客户端已显式设置或请求体截断时跳过；存储的请求正文
	// 仍保留客户端原始报文，仅转发体被改写。
	if reqResult.Parsed != nil && reqResult.Parsed.Stream &&
		reqResult.Classification.APIVariant == openai.VariantChat &&
		!truncated && len(body) > 0 {
		if modified, ok := openai.InjectStreamUsage(body); ok {
			body = modified
			sess.ParseStatus = append(sess.ParseStatus, "stream_usage_injected")
		}
	}

	respInfo, parseErr := p.forward(ctx, r, meta, body, tail, truncated, w)
	if parseErr != nil {
		sess.ParseStatus = append(sess.ParseStatus, "upstream_error")
	}
	sess.Response = respInfo
	sess.EndedAt = time.Now()

	parsedResp, err := openai.ParseResponse(respInfo)
	if err != nil {
		sess.ParseStatus = append(sess.ParseStatus, "response_parse_failed")
	} else if parsedResp != nil {
		sess.Classification = openai.RefineWithResponse(sess.Classification, parsedResp, reqResult.PathMatched, reqResult.HeaderSignal, knownHost)
		if parsedResp.Model != "" {
			sess.Model = parsedResp.Model
		}
		if parsedResp.Usage != nil {
			sess.Usage = parsedResp.Usage
		}
		if respInfo.Chunks > 0 && respInfo.ContentType != "" && strings.Contains(strings.ToLower(respInfo.ContentType), "text/event-stream") {
			sess.ParseStatus = append(sess.ParseStatus, "sse_aggregated")
		}
	}

	sess.Findings = p.detector.Inspect(buildDetectInput(sess, reqResult.Parsed, parsedResp, host, knownHost))
	sess.RequestSummary = detect.Redact(summarizeRequest(reqResult.Parsed))
	sess.ResponseSummary = detect.Redact(summarizeResponse(parsedResp))

	flow := p.toFlow(sess, host, path)
	if flow.Confidence == openai.ConfidenceNotAI && len(flow.Findings) == 0 {
		return
	}

	p.store.AddFlow(flow)
	// not_ai 流量按隐私约定不保留正文：即使命中了规则（例如普通请求里夹带凭据），
	// 也只落 Flow 摘要，不写详情。
	if flow.Confidence != openai.ConfidenceNotAI {
		p.store.AddFlowDetail(buildFlowDetail(flow, sess, reqResult.Parsed, parsedResp))
	}
	p.store.AddAlerts(p.toAlerts(flow))
	p.mu.Lock()
	p.flows++
	p.mu.Unlock()

	if len(flow.Findings) > 0 {
		p.logger.Printf("alert flow=%s host=%s path=%s findings=%d confidence=%s",
			flow.ID, flow.Host, flow.Path, len(flow.Findings), flow.Confidence)
	}
}

func (p *Pipeline) forward(ctx context.Context, r *http.Request, meta model.ConnMeta, body []byte, tail io.Reader, truncated bool, w http.ResponseWriter) (model.ResponseInfo, error) {
	info := model.ResponseInfo{}

	scheme := "http"
	if meta.IsTLS {
		scheme = "https"
	}
	outURL := &url.URL{
		Scheme:   r.URL.Scheme,
		Host:     r.URL.Host,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	if outURL.Scheme == "" {
		outURL.Scheme = scheme
	}
	if outURL.Host == "" {
		outURL.Host = r.Host
	}
	if outURL.Path == "" {
		outURL.Path = "/"
	}

	var bodyReader io.Reader
	contentLength := int64(len(body))
	if truncated {
		bodyReader = io.MultiReader(bytes.NewReader(body), tail)
		contentLength = r.ContentLength
		if contentLength <= int64(len(body)) {
			contentLength = -1
		}
	} else if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
		if r.ContentLength < 0 {
			contentLength = -1
		}
	} else if r.ContentLength < 0 {
		contentLength = -1
	}

	outReq := &http.Request{
		Method:        r.Method,
		URL:           outURL,
		Header:        cloneHeader(r.Header),
		Body:          readerCloser(bodyReader),
		ContentLength: contentLength,
		Host:          outURL.Host,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Close:         false,
	}
	removeHopByHop(outReq.Header)
	outReq.Header.Del("Accept-Encoding")
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		info.Status = http.StatusBadGateway
		info.Error = err.Error()
		info.Completed = false
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream unreachable","type":"gateway_error"}}`))
		return info, err
	}
	defer resp.Body.Close()

	info.Status = resp.StatusCode
	info.Headers = resp.Header.Clone()
	info.ContentType = resp.Header.Get("Content-Type")

	dstHeader := w.Header()
	for k, vals := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vals {
			dstHeader.Add(k, v)
		}
	}
	isSSE := strings.Contains(strings.ToLower(info.ContentType), "text/event-stream")
	if isSSE {
		dstHeader.Del("Content-Length")
	}
	dstHeader.Set("X-Lensgate", "inspected")
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	parser := &openai.SSEParser{}
	var capture bytes.Buffer
	captureLimit := p.cfg.MaxInspectBody
	buf := make([]byte, 32*1024)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			info.Chunks++
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				info.Error = writeErr.Error()
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
			if captureLimit > 0 && capture.Len() < captureLimit {
				want := n
				if remain := captureLimit - capture.Len(); want > remain {
					want = remain
				}
				capture.Write(buf[:want])
				if capture.Len() >= captureLimit {
					info.BodyTruncated = true
				}
			}
			if isSSE && len(info.SSE) < maxSSEEvents {
				info.SSE = append(info.SSE, parser.Feed(buf[:n])...)
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				info.Error = readErr.Error()
			}
			break
		}
	}
	if isSSE && len(info.SSE) < maxSSEEvents {
		info.SSE = append(info.SSE, parser.Close()...)
	}
	info.Body = capture.Bytes()
	info.Completed = info.Error == ""
	return info, nil
}

func buildDetectInput(sess *model.Session, req *openai.ParsedRequest, resp *openai.ParsedResponse, host string, knownHost bool) detect.Input {
	in := detect.Input{
		Host:       host,
		Confidence: sess.Classification.Confidence,
		KnownHost:  knownHost,
	}
	if req != nil {
		for i, m := range req.Messages {
			if m.Content != "" {
				in.RequestTexts = append(in.RequestTexts, detect.TextSpan{
					Field: fmt.Sprintf("messages[%d].content", i),
					Value: m.Content,
				})
			}
			for j, tc := range m.ToolCalls {
				in.RequestTools = append(in.RequestTools, detect.ToolSpan{
					Field:     fmt.Sprintf("messages[%d].tool_calls[%d]", i, j),
					Name:      tc.Name,
					Arguments: tc.Arguments,
				})
			}
		}
		if req.Instructions != "" {
			in.RequestTexts = append(in.RequestTexts, detect.TextSpan{Field: "instructions", Value: req.Instructions})
		}
		if req.Input != "" {
			in.RequestTexts = append(in.RequestTexts, detect.TextSpan{Field: "input", Value: req.Input})
		}
		for i, t := range req.Tools {
			in.RequestTools = append(in.RequestTools, detect.ToolSpan{
				Field:     fmt.Sprintf("tools[%d]", i),
				Name:      t.Name,
				Arguments: t.Description,
			})
		}
	}
	if resp != nil {
		if resp.Text != "" {
			in.ResponseTexts = append(in.ResponseTexts, detect.TextSpan{Field: "response.text", Value: resp.Text})
		}
		for i, tc := range resp.ToolCalls {
			in.ResponseCalls = append(in.ResponseCalls, detect.ToolSpan{
				Field:     fmt.Sprintf("response.tool_calls[%d]", i),
				Name:      tc.Name,
				Arguments: tc.Arguments,
			})
		}
	}
	return in
}

func (p *Pipeline) toFlow(sess *model.Session, host, path string) model.Flow {
	duration := sess.EndedAt.Sub(sess.StartedAt)
	if duration < 0 {
		duration = 0
	}
	orig := sess.Meta.OriginalDstString()
	if orig == "" {
		orig = sess.Meta.DstString()
	}
	return model.Flow{
		ID:              sess.ID,
		Ingress:         sess.Meta.Ingress,
		Src:             sess.Meta.SrcString(),
		Dst:             sess.Meta.DstString(),
		OriginalDst:     orig,
		SNI:             sess.Meta.SNI,
		Method:          sess.Request.Method,
		Host:            host,
		Path:            path,
		Status:          sess.Response.Status,
		ProtocolFamily:  sess.Classification.ProtocolFamily,
		APIVariant:      sess.Classification.APIVariant,
		Confidence:      sess.Classification.Confidence,
		Evidence:        sess.Classification.Evidence,
		ClientKind:      sess.Classification.ClientKind,
		ClientDetail:    sess.Classification.ClientDetail,
		ClientReason:    sess.Classification.ClientReason,
		Model:           sess.Model,
		Stream:          sess.Stream,
		Usage:           sess.Usage,
		RequestSummary:  sess.RequestSummary,
		ResponseSummary: sess.ResponseSummary,
		ParseStatus:     sess.ParseStatus,
		Findings:        sess.Findings,
		StartedAt:       sess.StartedAt,
		EndedAt:         sess.EndedAt,
		DurationMS:      duration.Milliseconds(),
	}
}

func (p *Pipeline) toAlerts(flow model.Flow) []model.Alert {
	if len(flow.Findings) == 0 {
		return nil
	}
	out := make([]model.Alert, 0, len(flow.Findings))
	now := time.Now()
	for _, f := range flow.Findings {
		out = append(out, model.Alert{
			ID:          newID(),
			FlowID:      flow.ID,
			RuleID:      f.RuleID,
			RuleName:    f.RuleName,
			Level:       f.Level,
			Direction:   f.Direction,
			FieldPath:   f.FieldPath,
			Evidence:    f.Evidence,
			Explanation: f.Explanation,
			Host:        flow.Host,
			Path:        flow.Path,
			CreatedAt:   now,
		})
	}
	return out
}

func summarizeRequest(pr *openai.ParsedRequest) string {
	if pr == nil {
		return ""
	}
	for i := len(pr.Messages) - 1; i >= 0; i-- {
		if strings.EqualFold(pr.Messages[i].Role, "user") && pr.Messages[i].Content != "" {
			return truncate(pr.Messages[i].Content, summaryRunes)
		}
	}
	if pr.Input != "" {
		return truncate(pr.Input, summaryRunes)
	}
	if pr.Instructions != "" {
		return truncate(pr.Instructions, summaryRunes)
	}
	if len(pr.Messages) > 0 {
		return truncate(pr.Messages[len(pr.Messages)-1].Content, summaryRunes)
	}
	return ""
}

func summarizeResponse(pr *openai.ParsedResponse) string {
	if pr == nil {
		return ""
	}
	if pr.Text != "" {
		return truncate(pr.Text, summaryRunes)
	}
	if len(pr.ToolCalls) > 0 {
		names := make([]string, 0, len(pr.ToolCalls))
		for _, tc := range pr.ToolCalls {
			names = append(names, tc.Name)
		}
		return "tool_calls: " + strings.Join(names, ", ")
	}
	if pr.Object != "" {
		return pr.Object
	}
	return ""
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "..."
}

func readRequestBody(rc io.ReadCloser, maxForward int64) (body []byte, truncated bool, tail io.Reader) {
	if rc == nil || rc == http.NoBody {
		return nil, false, nil
	}
	buf, _ := io.ReadAll(io.LimitReader(rc, maxForward+1))
	if int64(len(buf)) > maxForward {
		overflow := buf[maxForward:]
		return buf[:maxForward], true, io.MultiReader(bytes.NewReader(overflow), rc)
	}
	return buf, false, nil
}

func readerCloser(r io.Reader) io.ReadCloser {
	if r == nil {
		return http.NoBody
	}
	return io.NopCloser(r)
}

func hostOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	return strings.Trim(strings.ToLower(h), "[]")
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vals := range h {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

var hopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func isHopByHop(key string) bool {
	return hopHeaders[strings.ToLower(key)]
}

func removeHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for k := range h {
		if isHopByHop(k) {
			h.Del(k)
		}
	}
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func newUpstreamTLSConfig(cfg config.Config) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: cfg.UpstreamInsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}
