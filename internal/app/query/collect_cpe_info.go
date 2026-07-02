package query

import (
	"context"
	"log/slog"

	"cpe-api/internal/cpe"
	"cpe-api/internal/decorator"
	"cpe-api/internal/tcerr"

	"go.opentelemetry.io/otel/trace"
)

type CollectCpeInfo struct {
	IP      string             `json:"ip" binding:"required"`
	Port    int                `json:"port,omitempty"`
	Options cpe.CollectOptions `json:"options"`
}

type CollectCpeInfoHandler = decorator.QueryHandler[CollectCpeInfo, cpe.CollectResponse]

type CollectCpeInfoHandleModel interface {
	IsAllowedTarget(ip string) bool
	Collect(ctx context.Context, ip string, port int, options cpe.CollectOptions) cpe.CollectResponse
}

func NewCollectCpeInfoHandler(handleModel CollectCpeInfoHandleModel, logger *slog.Logger, tracer trace.Tracer) CollectCpeInfoHandler {
	return decorator.ApplyQueryDecorators(
		collectCpeInfoHandler{handleModel: handleModel},
		logger,
		tracer,
	)
}

type collectCpeInfoHandler struct {
	handleModel CollectCpeInfoHandleModel
}

func (handler collectCpeInfoHandler) Handle(ctx context.Context, query CollectCpeInfo) (cpe.CollectResponse, error) {
	if !handler.handleModel.IsAllowedTarget(query.IP) {
		return cpe.CollectResponse{}, tcerr.NewForbidden("target ip not allowed")
	}

	return handler.handleModel.Collect(ctx, query.IP, query.Port, query.Options), nil
}
