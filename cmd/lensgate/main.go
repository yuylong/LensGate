// Command lensgate 是网关主程序：装配接入层、核心管线、存储与控制台 API。
//
// 设计约定（见 AGENTS.md）：main 只做装配与生命周期管理，
// 协议识别/检测/转发逻辑全部在 internal/pipeline，
// 接入方式差异全部在 internal/ingress/*。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"lensgate/internal/api"
	"lensgate/internal/config"
	"lensgate/internal/detect"
	"lensgate/internal/ingress/explicit"
	"lensgate/internal/model"
	"lensgate/internal/pipeline"
	"lensgate/internal/proto/openai"
	"lensgate/internal/store"
	"lensgate/internal/tlsmitm"
)

func main() {
	cfgPath := flag.String("config", "config.json", "配置文件路径；不存在时使用内置默认值")
	proxyAddr := flag.String("proxy", "", "覆盖显式代理监听地址，例如 127.0.0.1:8080")
	apiAddr := flag.String("api", "", "覆盖控制台/API 监听地址，例如 127.0.0.1:8081")
	dataDir := flag.String("data-dir", "", "覆盖数据目录（flows.jsonl / alerts.jsonl / ca/）")
	insecureUpstream := flag.Bool("insecure-upstream", false, "跳过上游 TLS 校验；仅用于本地自签名 mock，接入真实服务时必须去掉")
	caStore := flag.String("ca-store", "user", "根证书导入范围：user（默认，免管理员）| machine（需管理员）| none（不自动导入）")
	flag.Parse()

	logger := log.New(os.Stdout, "[lensgate] ", log.LstdFlags)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Fatalf("加载配置失败：%v", err)
	}
	if *proxyAddr != "" {
		cfg.ProxyAddr = *proxyAddr
	}
	if *apiAddr != "" {
		cfg.APIAddr = *apiAddr
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *insecureUpstream {
		cfg.UpstreamInsecureSkipVerify = true
	}

	// 本地 CA：首次启动自动生成，用于 HTTPS MITM。
	caDir := filepath.Join(cfg.DataDir, "ca")
	ca, err := tlsmitm.LoadOrCreate(caDir)
	if err != nil {
		logger.Fatalf("初始化本地 CA 失败：%v", err)
	}
	caPath := filepath.Join(caDir, "ca.pem")

	// 默认把根证书导入当前用户信任库，让浏览器/curl 直接信任 MITM 证书。
	switch strings.ToLower(strings.TrimSpace(*caStore)) {
	case "none", "":
		if *caStore == "" {
			logger.Printf("根证书：未指定 -ca-store，跳过自动导入")
		}
	case "user", "machine":
		res := tlsmitm.EnsureTrusted(caPath, strings.ToLower(*caStore))
		if res.Changed {
			logger.Printf("根证书已导入系统信任库（%s）：%s", *caStore, res.Detail)
		} else if res.Trusted {
			logger.Printf("根证书已在系统信任库中（%s）", *caStore)
		} else {
			logger.Printf("根证书未导入（%s）：%s", *caStore, res.Detail)
		}
	default:
		logger.Printf("未知的 -ca-store=%q，支持 user|machine|none；本次跳过自动导入", *caStore)
	}

	st, err := store.New(cfg.DataDir, 0, 0)
	if err != nil {
		logger.Fatalf("初始化存储失败：%v", err)
	}
	defer st.Close()

	// 启动时用最新的指纹规则校正历史流量：JSONL 只保留了 UA，
	// 已识别为产品（如 Trae）的旧记录可据此升级类别。仅改内存，不回写文件。
	st.ReclassifyClients(func(f *model.Flow) {
		if kind, evidence := openai.DetectAppFromUA(f.ClientDetail); kind != "" {
			f.ClientKind = kind
			f.ClientReason = evidence
		}
	})

	detector := detect.New(cfg.Rules)
	pipe := pipeline.New(cfg, st, detector, logger)
	defer pipe.Close()

	startedAt := time.Now()
	proxy := explicit.New(cfg.ProxyAddr, ca, logger)
	apiSrv := api.New(cfg.APIAddr, st, detector, ca, cfg, startedAt, []string{proxy.Name()})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printBanner(logger, cfg, caPath)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- proxy.Serve(ctx, pipe.Handle)
	}()
	go func() {
		defer wg.Done()
		errCh <- apiSrv.Serve(ctx)
	}()

	select {
	case <-ctx.Done():
		logger.Printf("收到退出信号，正在关闭…")
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("服务异常退出：%v", err)
		}
	}

	stop()
	_ = apiSrv.Close()
	_ = proxy.Close()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logger.Printf("关闭超时，强制退出")
	}
	logger.Printf("已停止")
}

func printBanner(logger *log.Logger, cfg config.Config, caPath string) {
	console := cfg.APIAddr
	if host, port, err := net.SplitHostPort(console); err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			console = net.JoinHostPort("127.0.0.1", port)
		}
	}
	proxyURL := "http://" + cfg.ProxyAddr
	if host, port, err := net.SplitHostPort(cfg.ProxyAddr); err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			proxyURL = "http://127.0.0.1:" + port
		}
	}

	logger.Printf("网关已启动")
	logger.Printf("  控制台：    http://%s", console)
	logger.Printf("  显式代理：  %s", proxyURL)
	logger.Printf("  数据目录：  %s", cfg.DataDir)
	logger.Printf("  根证书：    %s", caPath)
	logger.Printf("  已知 AI 域名：%d 个", len(cfg.KnownAIHosts))
	if cfg.UpstreamInsecureSkipVerify {
		logger.Printf("  上游 TLS 校验：已跳过（仅本地 mock 演示）")
	}
	if len(cfg.Rules) > 0 {
		logger.Printf("  自定义规则：%d 条", len(cfg.Rules))
	}

	fmt.Fprintf(os.Stdout, `
使用方式示例（另开终端）：
  # 让 curl 走网关代理
  $env:HTTPS_PROXY = "%s"; $env:HTTP_PROXY = "%s"
  curl.exe -A "curl/8.7.1" -H "Authorization: Bearer sk-demo" ^
    -d '{\"model\":\"gpt-4o-mini\",\"messages\":[{\"role\":\"user\",\"content\":\"你好\"}]}' ^
    https://api.openai.com/v1/chat/completions

  # 或用演示客户端（先启动 mock：go run ./cmd/mock-openai）
  go run ./cmd/demo-client -scenario all

`, proxyURL, proxyURL)
}
