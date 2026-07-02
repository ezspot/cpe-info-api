package decorator

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

type commandLoggingDecorator[C any, R any] struct {
	base   CommandHandler[C, R]
	logger *slog.Logger
}

func (d commandLoggingDecorator[C, R]) Handle(ctx context.Context, cmd C) (result R, err error) {
	logger := d.logger.With("command", actionName(cmd))

	logger.Debug("command_started")
	defer func() {
		if err != nil {
			logger.Error("command_failed", "error", err)
			return
		}
		logger.Debug("command_succeeded")
	}()

	return d.base.Handle(ctx, cmd)
}

type queryLoggingDecorator[Q any, R any] struct {
	base   QueryHandler[Q, R]
	logger *slog.Logger
}

func (d queryLoggingDecorator[Q, R]) Handle(ctx context.Context, query Q) (result R, err error) {
	logger := d.logger.With("query", actionName(query))

	logger.Debug("query_started")
	defer func() {
		if err != nil {
			logger.Error("query_failed", "error", err)
			return
		}
		logger.Debug("query_succeeded")
	}()

	return d.base.Handle(ctx, query)
}

func actionName(action any) string {
	parts := strings.Split(fmt.Sprintf("%T", action), ".")
	return parts[len(parts)-1]
}
