package api

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lensgate/internal/config"
	"lensgate/internal/detect"
	"lensgate/internal/model"
	"lensgate/internal/store"
	"lensgate/internal/tlsmitm"
)

const Version = "0.1.0"

//go:embed static
var staticFS embed.FS

type Server struct {
	Addr      string
	Store     *store.Store
	Detector  *detect.Detector
	CA        *tlsmitm.CA
	Config    config.Config
	StartedAt time.Time
	Ingresses []string

	srv *http.Server
	ln  net.Listener
}

func New(addr string, st *store.Store, det *detect.Detector, ca *tlsmitm.CA, cfg config.Config, startedAt time.Time, ingresses []string) *Server {
	return &Server{
		Addr:      addr,
		Store:     st,
		Detector:  det,
		CA:        ca,
		Config:    cfg,
		StartedAt: startedAt,
		Ingresses: ingresses,
	}
}

func (s *Server) Serve(ctx context.Context) error {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/ca.pem", s.handleCA)
	mux.Handle("/", http.FileServer(http.FS(sub)))

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	return s.srv.Serve(ln)
}

func (s *Server) Close() error {
	if s.srv != nil {
		return s.srv.Close()
	}
	return nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	stats := s.Store.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"version":          Version,
		"started_at":       s.StartedAt,
		"uptime_seconds":   int64(time.Since(s.StartedAt).Seconds()),
		"proxy_addr":       s.Config.ProxyAddr,
		"api_addr":         s.Config.APIAddr,
		"data_dir":         s.Config.DataDir,
		"ingresses":        s.Ingresses,
		"max_inspect_body": s.Config.MaxInspectBody,
		"known_ai_hosts":   s.Config.KnownAIHosts,
		"flows":            stats.TotalFlows,
		"alerts":           stats.TotalAlerts,
		"ca_download":      "/api/ca.pem",
	})
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	flows := s.Store.Flows(queryLimit(r, 200, 1000))
	if flows == nil {
		flows = []model.Flow{}
	}
	writeJSON(w, http.StatusOK, flows)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	alerts := s.Store.Alerts(queryLimit(r, 200, 1000))
	if alerts == nil {
		alerts = []model.Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.Store.Stats())
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, s.Detector.Rules())
}

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="lensgate-ca.pem"`)
	_, _ = w.Write(s.CA.CertPEM())
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	events, cancel := s.Store.Subscribe()
	defer cancel()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-events:
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func queryLimit(r *http.Request, def, max int) int {
	v := strings.TrimSpace(r.URL.Query().Get("limit"))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
