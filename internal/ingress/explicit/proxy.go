package explicit

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"lensgate/internal/ingress"
	"lensgate/internal/model"
	"lensgate/internal/tlsmitm"
)

// Proxy 实现显式 HTTP/HTTPS 正向代理，并对 HTTPS 做本地 MITM。
// 所有请求最终都交给 ingress.Handler，本身不做协议识别或安全检测。
type Proxy struct {
	Addr   string
	CA     *tlsmitm.CA
	Logger *log.Logger

	mu     sync.Mutex
	ln     net.Listener
	closed bool
}

func New(addr string, ca *tlsmitm.CA, logger *log.Logger) *Proxy {
	return &Proxy{Addr: addr, CA: ca, Logger: logger}
}

func (p *Proxy) Name() string { return "explicit" }

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

// ServeListener 便于测试注入 127.0.0.1:0 监听器。
func (p *Proxy) ServeListener(ctx context.Context, ln net.Listener, h ingress.Handler) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || p.isClosed() {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go p.handleConn(ctx, conn, h)
	}
}

func (p *Proxy) handleConn(ctx context.Context, conn net.Conn, h ingress.Handler) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := br.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Fields(line)
	if len(fields) < 2 {
		writeStatus(conn, http.StatusBadRequest)
		return
	}

	if strings.EqualFold(fields[0], http.MethodConnect) {
		p.handleConnect(ctx, conn, br, fields[1], h)
		return
	}

	p.handlePlainHTTP(ctx, conn, br, line, h)
}

func (p *Proxy) handleConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, target string, h ingress.Handler) {
	if err := drainHeaders(br); err != nil {
		return
	}
	host, port := ingress.SplitHostPort(target, "443")
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: lensgate\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(ingress.NewBufferedConn(conn, br), p.CA.TLSConfig())
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		p.logf("mitm handshake %s failed: %v", target, err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	state := tlsConn.ConnectionState()
	sni := state.ServerName
	if sni == "" {
		sni = host
	}
	meta := model.ConnMeta{
		Ingress: "explicit",
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

func (p *Proxy) handlePlainHTTP(ctx context.Context, conn net.Conn, br *bufio.Reader, requestLine string, h ingress.Handler) {
	rc := ingress.NewReplayConn(conn, []byte(requestLine+"\r\n"), br)
	base := model.ConnMeta{
		Ingress: "explicit",
		Src:     ingress.AddrPort(conn.RemoteAddr()),
	}
	metaFn := func(r *http.Request) model.ConnMeta {
		m := base
		hostport := r.URL.Host
		if hostport == "" {
			hostport = r.Host
		}
		host, port := ingress.SplitHostPort(hostport, "80")
		m.DstHost = host
		m.DstPort = port
		return m
	}
	_ = ingress.ServeHTTPConn(rc, metaFn, h)
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

func drainHeaders(br *bufio.Reader) error {
	for i := 0; i < 200; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "" {
			return nil
		}
	}
	return errors.New("too many headers")
}

func writeStatus(conn net.Conn, code int) {
	text := http.StatusText(code)
	if text == "" {
		text = "Bad Request"
	}
	_, _ = conn.Write([]byte("HTTP/1.1 " + itoa(code) + " " + text + "\r\nConnection: close\r\n\r\n"))
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
