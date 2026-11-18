package ingress

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"lensgate/internal/model"
)

// Handler 是核心业务唯一依赖的 HTTP 入口。
// 显式代理、透明代理、TUN/WFP 只需要把字节流还原成 HTTP 请求，再调用它。
type Handler func(ctx context.Context, meta model.ConnMeta, w http.ResponseWriter, r *http.Request)

// Ingress 抽象“流量怎么进来”，不包含任何检测或转发逻辑。
type Ingress interface {
	Name() string
	Serve(ctx context.Context, h Handler) error
	Close() error
}

// ServeHTTPConn 在单条连接上运行 HTTP/1.1 服务端。
// 这样显式代理和透明代理都能复用同一套 HTTP 处理逻辑。
func ServeHTTPConn(conn net.Conn, metaFn func(*http.Request) model.ConnMeta, h Handler) error {
	sc := &closeSignalConn{Conn: conn, done: make(chan struct{})}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h(r.Context(), metaFn(r), w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	ln := &singleConnListener{conn: sc}
	err := srv.Serve(ln)
	// Serve 在 Accept 到 EOF 后立即返回，但连接处理仍在 goroutine 中。
	// 等待 http.Server 真正关闭连接，调用方才能安全地做清理。
	if ln.served {
		<-sc.done
	}
	return err
}

// closeSignalConn 在连接被 http.Server 关闭时发出信号。
type closeSignalConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *closeSignalConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

type singleConnListener struct {
	conn   net.Conn
	served bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.served {
		return nil, io.EOF
	}
	l.served = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// BufferedConn 让 TLS 握手和 HTTP 解析共享同一个 bufio.Reader 中已缓冲的字节。
type BufferedConn struct {
	net.Conn
	R *bufio.Reader
}

func NewBufferedConn(c net.Conn, r *bufio.Reader) *BufferedConn {
	return &BufferedConn{Conn: c, R: r}
}

func (c *BufferedConn) Read(b []byte) (int, error) { return c.R.Read(b) }

// ReplayConn 先回放已经读取的字节，再继续读底层连接。
// 用于显式代理先读请求行判断 CONNECT，又不丢失普通 HTTP 请求。
type ReplayConn struct {
	net.Conn
	prefix []byte
	R      *bufio.Reader
}

func NewReplayConn(c net.Conn, prefix []byte, r *bufio.Reader) *ReplayConn {
	return &ReplayConn{Conn: c, prefix: prefix, R: r}
}

func (c *ReplayConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.R.Read(b)
}

// AddrPort 把 net.Addr 归一化为 netip.AddrPort；主机名无法表示时返回零值。
func AddrPort(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}

// SplitHostPort 解析 host:port，缺省端口由 def 提供。
func SplitHostPort(target, def string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = def
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil || port <= 0 || port > 65535 {
		port, _ = strconv.Atoi(def)
	}
	return host, uint16(port)
}
