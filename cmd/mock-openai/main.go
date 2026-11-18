package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"lensgate/internal/mockopenai"
)

func main() {
	httpAddr := flag.String("http", "127.0.0.1:18080", "HTTP 监听地址，留空则关闭")
	tlsAddr := flag.String("https", "127.0.0.1:18443", "HTTPS 监听地址（自签名），留空则关闭")
	flag.Parse()

	logger := log.New(os.Stdout, "[mock-openai] ", log.LstdFlags)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv := mockopenai.New(*httpAddr, *tlsAddr, logger)
	logger.Printf("HTTP=%s HTTPS=%s", *httpAddr, *tlsAddr)
	if err := srv.Serve(ctx); err != nil {
		logger.Fatalf("mock server failed: %v", err)
	}
}
