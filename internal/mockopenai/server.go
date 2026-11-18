package mockopenai

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

// Server 模拟 OpenAI Chat Completions / Responses / Embeddings 以及 Azure 部署路径。
// 它同时提供 HTTP 和自签名 HTTPS，用于验证代理的 MITM 与协议识别。
type Server struct {
	HTTPAddr string
	TLSAddr  string
	Logger   *log.Logger

	httpSrv *http.Server
	tlsSrv  *http.Server
}

func New(httpAddr, tlsAddr string, logger *log.Logger) *Server {
	return &Server{HTTPAddr: httpAddr, TLSAddr: tlsAddr, Logger: logger}
}

func (s *Server) Serve(ctx context.Context) error {
	mux := s.routes()

	errCh := make(chan error, 2)
	if s.HTTPAddr != "" {
		ln, err := net.Listen("tcp", s.HTTPAddr)
		if err != nil {
			return err
		}
		s.httpSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { errCh <- s.httpSrv.Serve(ln) }()
	}
	if s.TLSAddr != "" {
		cert, err := selfSigned()
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", s.TLSAddr)
		if err != nil {
			return err
		}
		s.tlsSrv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		}
		go func() { errCh <- s.tlsSrv.ServeTLS(ln, "", "") }()
	}

	select {
	case <-ctx.Done():
		s.Close()
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) Close() {
	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
	}
	if s.tlsSrv != nil {
		_ = s.tlsSrv.Close()
	}
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleChat)
	mux.HandleFunc("/api/v1/chat/completions", s.handleChat)
	mux.HandleFunc("/openai/deployments/", s.handleAzure)
	mux.HandleFunc("/v1/responses", s.handleResponses)
	mux.HandleFunc("/v1/embeddings", s.handleEmbeddings)
	mux.HandleFunc("/v1/models", s.handleModels)
	mux.HandleFunc("/", s.handleIndex)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "mock OpenAI server\n\nPOST /v1/chat/completions\nPOST /v1/responses\nPOST /v1/embeddings\nPOST /openai/deployments/{deployment}/chat/completions\nPOST /api/v1/chat/completions\n")
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"object": "list",
		"data": []map[string]any{
			{"id": "gpt-4o-mini", "object": "model", "owned_by": "mock"},
			{"id": "text-embedding-3-small", "object": "model", "owned_by": "mock"},
		},
	})
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Type     string `json:"type"`
		Function struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"function"`
	} `json:"tools"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req chatRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.serveChat(w, req)
}

func (s *Server) serveChat(w http.ResponseWriter, req chatRequest) {
	model := req.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	text := s.replyText(req)
	toolName, toolArgs := "", ""
	if strings.Contains(lastUserText(req), "执行命令") && len(req.Tools) > 0 {
		toolName = req.Tools[0].Function.Name
		toolArgs = `{"command":"rm -rf /tmp/demo"}`
	}

	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		id := "chatcmpl-mock-" + time.Now().Format("150405.000")
		chunks := splitRunes(text, 12)
		for i, part := range chunks {
			delta := map[string]any{"content": part}
			if i == 0 {
				delta["role"] = "assistant"
			}
			payload := map[string]any{
				"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
				"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": nil}},
			}
			writeSSE(w, payload)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
		final := map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
			"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
		}
		writeSSE(w, final)
		writeSSE(w, map[string]any{
			"id": id, "object": "chat.completion.chunk", "model": model,
			"choices": []any{},
			"usage":   map[string]any{"prompt_tokens": 42, "completion_tokens": 28, "total_tokens": 70},
		})
		fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	message := map[string]any{"role": "assistant", "content": text}
	finish := "stop"
	if toolName != "" {
		message = map[string]any{"role": "assistant", "content": nil}
		message["tool_calls"] = []map[string]any{{
			"id": "call_mock_1", "type": "function",
			"function": map[string]any{"name": toolName, "arguments": toolArgs},
		}}
		finish = "tool_calls"
	}
	writeJSON(w, map[string]any{
		"id": "chatcmpl-mock", "object": "chat.completion", "created": time.Now().Unix(), "model": model,
		"choices": []map[string]any{{"index": 0, "message": message, "finish_reason": finish}},
		"usage":   map[string]any{"prompt_tokens": 42, "completion_tokens": 28, "total_tokens": 70},
	})
}

func (s *Server) handleAzure(w http.ResponseWriter, r *http.Request) {
	// /openai/deployments/{deployment}/chat/completions
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	deployment := ""
	if len(parts) >= 3 && parts[0] == "openai" && parts[1] == "deployments" {
		deployment = parts[2]
	}
	var req chatRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req)
	if req.Model == "" {
		req.Model = deployment
	}
	s.serveChat(w, req)
}

func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
		Input  any    `json:"input"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	model := req.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	text := "这是 mock Responses API 的文本输出。"
	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		writeEvent(w, "response.created", map[string]any{
			"type":     "response.created",
			"response": map[string]any{"id": "resp_mock", "model": model, "status": "in_progress"},
		})
		for _, part := range splitRunes(text, 10) {
			writeEvent(w, "response.output_text.delta", map[string]any{
				"type": "response.output_text.delta", "delta": part,
			})
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(20 * time.Millisecond)
		}
		writeEvent(w, "response.completed", map[string]any{
			"type": "response.completed",
			"response": map[string]any{
				"id": "resp_mock", "model": model, "status": "completed",
				"output": []map[string]any{{
					"type": "message", "role": "assistant",
					"content": []map[string]any{{"type": "output_text", "text": text}},
				}},
				"usage": map[string]any{"input_tokens": 36, "output_tokens": 22, "total_tokens": 58},
			},
		})
		if flusher != nil {
			flusher.Flush()
		}
		return
	}
	writeJSON(w, map[string]any{
		"id": "resp_mock", "object": "response", "created_at": time.Now().Unix(), "model": model, "status": "completed",
		"output": []map[string]any{{
			"type": "message", "role": "assistant",
			"content": []map[string]any{{"type": "output_text", "text": text}},
		}},
		"usage": map[string]any{"input_tokens": 36, "output_tokens": 22, "total_tokens": 58},
	})
}

func (s *Server) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Model string `json:"model"`
		Input any    `json:"input"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	model := req.Model
	if model == "" {
		model = "text-embedding-3-small"
	}
	writeJSON(w, map[string]any{
		"object": "list", "model": model,
		"data":  []map[string]any{{"object": "embedding", "index": 0, "embedding": []float64{0.0123, -0.0456, 0.0789}}},
		"usage": map[string]any{"prompt_tokens": 8, "total_tokens": 8},
	})
}

func (s *Server) replyText(req chatRequest) string {
	last := lastUserText(req)
	if last == "" {
		last = "（空输入）"
	}
	if len([]rune(last)) > 80 {
		last = string([]rune(last)[:80]) + "..."
	}
	return "这是 mock OpenAI 服务的回答。已收到 " + fmt.Sprint(len(req.Messages)) + " 条消息。最后一条用户输入：" + last
}

func lastUserText(req chatRequest) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role != "user" {
			continue
		}
		var s string
		if json.Unmarshal(req.Messages[i].Content, &s) == nil {
			return s
		}
		var parts []map[string]any
		if json.Unmarshal(req.Messages[i].Content, &parts) == nil {
			var sb strings.Builder
			for _, p := range parts {
				if t, ok := p["text"].(string); ok {
					sb.WriteString(t)
				}
			}
			return sb.String()
		}
	}
	return ""
}

func splitRunes(s string, size int) []string {
	r := []rune(s)
	var out []string
	for i := 0; i < len(r); i += size {
		end := i + size
		if end > len(r) {
			end = len(r)
		}
		out = append(out, string(r[i:end]))
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeSSE(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "data: %s\n\n", b)
}

func writeEvent(w http.ResponseWriter, name string, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b)
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mock-openai.local"},
		DNSNames:     []string{"localhost", "mock-openai.local"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
