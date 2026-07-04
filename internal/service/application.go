package service

import (
	"log/slog"

	"device-api/internal/app"
	"device-api/internal/app/command"
	"device-api/internal/app/query"
	"device-api/internal/config"
	"device-api/internal/cpe"
	"device-api/internal/observability"
	"device-api/internal/snmp"

	"go.opentelemetry.io/otel"
)

func NewApplication(cfg config.Config, logger *slog.Logger, metrics *observability.Registry) (*app.Application, error) {
	collector, err := cpe.NewCollector(cfg, logger, metrics)
	if err != nil {
		return nil, err
	}

	snmpCollector := snmp.NewCollector(cfg.SNMP, logger, metrics)

	tracer := otel.Tracer("device-api")

	return &app.Application{
		Commands: app.Commands{
			PerformCpeAction: command.NewPerformCpeActionHandler(collector, logger, tracer),
		},
		Queries: app.Queries{
			CollectCpeInfo:    query.NewCollectCpeInfoHandler(collector, logger, tracer),
			CollectSwitchPort: query.NewCollectSwitchPortHandler(snmpCollector, logger, tracer),
		},
	}, nil
}
