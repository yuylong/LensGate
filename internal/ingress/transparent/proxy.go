package transparent

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"lensgate/internal/ingress"
	"lensgate/internal/model"
	"lensgate/internal/tlsmitm"
)

// Proxy 是透明代理的本地模拟适配器。
// 真实网关通常由 WFP/iptables/nftables 把流量重定向到监听端口，本实现用固定目标地址模拟。
// 关键点：它复用了同一个 ingress.Handler，上层业务逻辑无需修改。
type Proxy struct {
	Addr   string
	Target string
	CA     *tlsmitm.CA
	Logger *log.Logger

	mu     sync.Mutex
	ln     net.Listener
	closed bool
}

func New(addr, target string, ca *tlsmitm.CA, logger *log.Logger) *Proxy {
	return &Proxy{Addr: addr, Target: target, CA: ca, Logger: logger}
}

func (p *Proxy) Name() string { return "transparent-sim" }

func (p *Proxy) Serve(ctx context.Context, h ingress.Handler) error {
	ln, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = p.Close()
	}()
	return p.ServeListener(ctx, ln, h)
}

func (p *Proxy) ServeListener(ctx context.Context, ln net.Listener, h ingress.Handler) error {
	host, port := ingress.SplitHostPort(p.Target, "443")
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || p.isClosed() {
				return nil
			}
			return err
		}
		go p.handleConn(conn, host, port, h)
	}
}

func (p *Proxy) handleConn(conn net.Conn, host string, port uint16, h ingress.Handler) {
	defer conn.Close()

	tlsConn := tls.Server(conn, p.CA.TLSConfig())
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		p.logf("transparent handshake failed: %v", err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	state := tlsConn.ConnectionState()
	sni := state.ServerName
	if sni == "" {
		sni = host
	}
	meta := model.ConnMeta{
		Ingress: "transparent-sim",
		Src:     ingress.AddrPort(conn.RemoteAddr()),
		DstHost: host,
		DstPort: port,
		SNI:     sni,
		IsTLS:   true,
	}
	if state.NegotiatedProtocol != "" {
		meta.ALPN = []string{state.NegotiatedProtocol}
	}

	_ = ingress.ServeHTTPConn(tlsConn, func(*http.Request) model.ConnMeta { return meta }, h)
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.ln != nil {
		return p.ln.Close()
	}
	return nil
}

func (p *Proxy) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Logger != nil {
		p.Logger.Printf(format, args...)
	}
}
