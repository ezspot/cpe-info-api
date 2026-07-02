package service

import (
	"log/slog"

	"cpe-api/internal/app"
	"cpe-api/internal/app/command"
	"cpe-api/internal/app/query"
	"cpe-api/internal/config"
	"cpe-api/internal/cpe"
	"cpe-api/internal/observability"

	"go.opentelemetry.io/otel"
)

func NewApplication(cfg config.Config, logger *slog.Logger, metrics *observability.Registry) (*app.Application, error) {
	collector, err := cpe.NewCollector(cfg, logger, metrics)
	if err != nil {
		return nil, err
	}

	tracer := otel.Tracer("cpe-api")

	return &app.Application{
		Commands: app.Commands{
			PerformCpeAction: command.NewPerformCpeActionHandler(collector, logger, tracer),
		},
		Queries: app.Queries{
			CollectCpeInfo: query.NewCollectCpeInfoHandler(collector, logger, tracer),
		},
	}, nil
}
