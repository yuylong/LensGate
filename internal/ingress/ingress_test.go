package ingress_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"lensgate/internal/ingress"
	"lensgate/internal/ingress/explicit"
	"lensgate/internal/ingress/transparent"
	"lensgate/internal/model"
	"lensgate/internal/tlsmitm"
)

type captured struct {
	meta model.ConnMeta
	path string
}

func captureHandler(ch chan<- captured) ingress.Handler {
	return func(ctx context.Context, meta model.ConnMeta, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		select {
		case ch <- captured{meta: meta, path: r.URL.Path}:
		default:
		}
	}
}

func waitCapture(t *testing.T, ch <-chan captured) captured {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("handler was not called")
		return captured{}
	}
}

// TestIngressParity 验证显式代理与透明模拟适配器把同样的连接归一化成相同的元数据。
func TestIngressParity(t *testing.T) {
	ca, err := tlsmitm.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan captured, 2)
	h := captureHandler(ch)

	// 显式正向代理
	lnExp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	exp := explicit.New("", ca, nil)
	go exp.ServeListener(ctx, lnExp, h)
	proxyURL, _ := url.Parse("http://" + lnExp.Addr().String())
	expClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	post(t, expClient, "https://example.test/v1/chat/completions")
	expCap := waitCapture(t, ch)

	// 透明代理模拟：固定目标地址，复用同一个 Handler
	lnTr, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := transparent.New("", "example.test:443", ca, nil)
	go tr.ServeListener(ctx, lnTr, h)
	trClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", lnTr.Addr().String())
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	post(t, trClient, "https://example.test/v1/chat/completions")
	trCap := waitCapture(t, ch)

	if expCap.meta.Ingress != "explicit" {
		t.Fatalf("explicit ingress = %q", expCap.meta.Ingress)
	}
	if trCap.meta.Ingress != "transparent-sim" {
		t.Fatalf("transparent ingress = %q", trCap.meta.Ingress)
	}
	if !expCap.meta.IsTLS || !trCap.meta.IsTLS {
		t.Fatal("both ingresses should terminate TLS")
	}
	if expCap.meta.DstString() != trCap.meta.DstString() {
		t.Fatalf("dst mismatch: %q vs %q", expCap.meta.DstString(), trCap.meta.DstString())
	}
	if expCap.meta.SNI != "example.test" || trCap.meta.SNI != "example.test" {
		t.Fatalf("sni mismatch: %q vs %q", expCap.meta.SNI, trCap.meta.SNI)
	}
	if expCap.path != "/v1/chat/completions" || trCap.path != "/v1/chat/completions" {
		t.Fatalf("path mismatch: %q vs %q", expCap.path, trCap.path)
	}
}

func post(t *testing.T, client *http.Client, target string) {
	t.Helper()
	resp, err := client.Post(target, "application/json", strings.NewReader(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
