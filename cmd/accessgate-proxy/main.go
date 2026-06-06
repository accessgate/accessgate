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

	handler, engine, tracerShutdown, err := buildProxyHandler(context.Background(), cfg)
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

	// Optional gRPC server (enabled when grpc_listen_addr is set). It shares the
	// authz engine with the HTTP server and installs the AccessGate authz
	// interceptors on every call.
	grpcSrv := newGRPCServer(engine)
	grpcEnabled := cfg.GRPCListenAddr != ""
	if grpcEnabled {
		lis, err := startGRPCServer(grpcSrv, cfg.GRPCListenAddr)
		if err != nil {
			logger.Fatalf("grpc listen %q: %v", cfg.GRPCListenAddr, err)
		}
		logger.Printf("grpc server listening on %s", lis.Addr().String())
	}

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

	if grpcEnabled {
		// GracefulStop blocks until in-flight RPCs complete. Bound it by the
		// shutdown deadline by racing against a hard Stop.
		done := make(chan struct{})
		go func() {
			grpcSrv.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-shutdownCtx.Done():
			logger.Printf("grpc graceful shutdown timed out; forcing stop")
			grpcSrv.Stop()
		}
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}
}
