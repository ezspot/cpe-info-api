package query

import (
	"context"
	"log/slog"

	"device-api/internal/decorator"
	"device-api/internal/snmp"
	"device-api/internal/tcerr"

	"go.opentelemetry.io/otel/trace"
)

type CollectSwitchPort struct {
	Host             string `json:"host" binding:"required"`
	Port             string `json:"port,omitempty"`
	ReverseDirection bool   `json:"reverseDirection,omitempty"`
	IncludeMACs      bool   `json:"includeMacs,omitempty"`
}

type CollectSwitchPortHandler = decorator.QueryHandler[CollectSwitchPort, snmp.PortResponse]

type CollectSwitchPortHandleModel interface {
	IsAllowedTarget(ip string) bool
	CollectPorts(ctx context.Context, query snmp.PortQuery) snmp.PortResponse
}

func NewCollectSwitchPortHandler(handleModel CollectSwitchPortHandleModel, logger *slog.Logger, tracer trace.Tracer) CollectSwitchPortHandler {
	return decorator.ApplyQueryDecorators(
		collectSwitchPortHandler{handleModel: handleModel},
		logger,
		tracer,
	)
}

type collectSwitchPortHandler struct {
	handleModel CollectSwitchPortHandleModel
}

func (handler collectSwitchPortHandler) Handle(ctx context.Context, query CollectSwitchPort) (snmp.PortResponse, error) {
	if !handler.handleModel.IsAllowedTarget(query.Host) {
		return snmp.PortResponse{}, tcerr.NewForbidden("target host not allowed")
	}

	return handler.handleModel.CollectPorts(ctx, snmp.PortQuery{
		Host:             query.Host,
		Port:             query.Port,
		ReverseDirection: query.ReverseDirection,
		IncludeMACs:      query.IncludeMACs,
	}), nil
}
