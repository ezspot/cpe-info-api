// @title CPE Info API
// @version 1.0
// @description Collect CPE diagnostics over SSH with model-aware authentication.
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Use `Bearer <token>`.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cpe-api/internal/config"
	"cpe-api/internal/observability"
	"cpe-api/internal/ports"
	"cpe-api/internal/service"
)

func main() {
	cfg := config.MustLoad()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	allowedCIDRs := make([]string, 0, len(cfg.AllowedTargetCIDRs))
	for _, n := range cfg.AllowedTargetCIDRs {
		allowedCIDRs = append(allowedCIDRs, n.String())
	}
	logger.Info("config_loaded",
		"addr", cfg.Addr,
		"allowed_target_cidrs", allowedCIDRs,
		"has_api_key", cfg.APIKey != "",
		"ssh_keys_dir", cfg.SSHKeysDir,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := observability.SetupTracing(ctx, "cpe-info-api")
	if err != nil {
		logger.Error("tracing init failed", "error", err)
		os.Exit(1)
	}

	metrics := observability.NewRegistry()

	application, err := service.NewApplication(cfg, logger, metrics)
	if err != nil {
		logger.Error("application init failed", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           ports.NewHttpServer(application, cfg, logger, metrics),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server starting", "addr", cfg.Addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
	if err := shutdownTracing(shutdownCtx); err != nil {
		logger.Error("tracing shutdown failed", "error", err)
	}

	logger.Info("shutdown complete")
}
