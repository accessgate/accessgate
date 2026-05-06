package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := log.New(os.Stdout, "[accessgate-proxy] ", log.LstdFlags|log.LUTC)
	logger.Println("starting accessgate-proxy")

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatalf("config load: %v", err)
	}

	handler, tracerShutdown, err := buildProxyHandler(context.Background(), cfg)
	if err != nil {
		logger.Fatalf("proxy bootstrap: %v", err)
	}

	srv := &http.Server{
		Addr:    ":" + cfg.HTTPPort,
		Handler: handler,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http server error: %v", err)
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-sigCtx.Done()
	logger.Println("shutting down accessgate-proxy")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if tracerShutdown != nil {
		tracerCtx, tracerCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer tracerCancel()
		if err := tracerShutdown(tracerCtx); err != nil {
			logger.Printf("tracer shutdown: %v", err)
		}
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}
}
