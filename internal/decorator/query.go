package decorator

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

type QueryHandler[Q any, R any] interface {
	Handle(ctx context.Context, query Q) (R, error)
}

func ApplyQueryDecorators[Q any, R any](handler QueryHandler[Q, R], logger *slog.Logger, tracer trace.Tracer) QueryHandler[Q, R] {
	return queryLoggingDecorator[Q, R]{
		base: queryTracingDecorator[Q, R]{
			base:   handler,
			tracer: tracer,
		},
		logger: logger,
	}
}
