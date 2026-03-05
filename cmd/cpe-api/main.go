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
	"cpe-api/internal/cpe"
	"cpe-api/internal/httpapi"
)

func main() {
	cfg := config.MustLoad()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

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

	collector, err := cpe.NewCollector(cfg, logger)
	if err != nil {
		logger.Error("collector init failed", "error", err)
		os.Exit(1)
	}

	handler := httpapi.NewServer(cfg, logger, collector)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
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

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}

	logger.Info("shutdown complete")
}
