package decorator

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

type CommandHandler[C any, R any] interface {
	Handle(ctx context.Context, cmd C) (R, error)
}

func ApplyCommandDecorators[C any, R any](handler CommandHandler[C, R], logger *slog.Logger, tracer trace.Tracer) CommandHandler[C, R] {
	return commandLoggingDecorator[C, R]{
		base: commandTracingDecorator[C, R]{
			base:   handler,
			tracer: tracer,
		},
		logger: logger,
	}
}
