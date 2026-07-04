package command

import (
	"context"
	"log/slog"

	"device-api/internal/cpe"
	"device-api/internal/decorator"
	"device-api/internal/tcerr"

	"go.opentelemetry.io/otel/trace"
)

type PerformCpeAction struct {
	IP      string            `json:"ip" binding:"required"`
	Port    int               `json:"port,omitempty"`
	Options cpe.ActionOptions `json:"options"`
}

type PerformCpeActionResult struct {
	Response cpe.ActionResponse `json:"response"`
}

type PerformCpeActionHandler = decorator.CommandHandler[PerformCpeAction, PerformCpeActionResult]

type PerformCpeActionHandleModel interface {
	IsAllowedTarget(ip string) bool
	PerformAction(ctx context.Context, ip string, port int, options cpe.ActionOptions) cpe.ActionResponse
}

func NewPerformCpeActionHandler(handleModel PerformCpeActionHandleModel, logger *slog.Logger, tracer trace.Tracer) PerformCpeActionHandler {
	return decorator.ApplyCommandDecorators(
		performCpeActionHandler{handleModel: handleModel},
		logger,
		tracer,
	)
}

type performCpeActionHandler struct {
	handleModel PerformCpeActionHandleModel
}

func (handler performCpeActionHandler) Handle(ctx context.Context, cmd PerformCpeAction) (res PerformCpeActionResult, err error) {
	if !handler.handleModel.IsAllowedTarget(cmd.IP) {
		err = tcerr.NewForbidden("target ip not allowed")
		return
	}
	res.Response = handler.handleModel.PerformAction(ctx, cmd.IP, cmd.Port, cmd.Options)
	return
}
