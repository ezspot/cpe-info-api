// @title Device API
// @version 1.0
// @description Collect diagnostics from CPEs over SSH and from switches over SNMP.
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Paste the API key value directly (a `Bearer ` prefix is also accepted).
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"device-api/internal/config"
	"device-api/internal/observability"
	"device-api/internal/ports"
	"device-api/internal/service"
	"device-api/internal/snmp"
)

func main() {
	if err := config.LoadDotEnv(".env"); err != nil {
		log.Printf("warning: could not read .env: %v", err)
	}

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

	shutdownTracing, err := observability.SetupTracing(ctx, "device-api")
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

	var hostResolver *snmp.HostResolver
	if cfg.SwitchHostsFile != "" {
		hostResolver, err = snmp.NewHostResolver(cfg.SwitchHostsFile)
		if err != nil {
			logger.Error("switch hosts file load failed", "error", err)
			os.Exit(1)
		}
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           ports.NewHttpServer(application, cfg, logger, metrics, hostResolver),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
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
