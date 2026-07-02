package decorator

import (
	"context"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type commandTracingDecorator[C any, R any] struct {
	base   CommandHandler[C, R]
	tracer trace.Tracer
}

func (d commandTracingDecorator[C, R]) Handle(ctx context.Context, cmd C) (R, error) {
	ctx, span := d.tracer.Start(ctx, actionName(cmd))
	defer span.End()

	result, err := d.base.Handle(ctx, cmd)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	return result, err
}

type queryTracingDecorator[Q any, R any] struct {
	base   QueryHandler[Q, R]
	tracer trace.Tracer
}

func (d queryTracingDecorator[Q, R]) Handle(ctx context.Context, query Q) (R, error) {
	ctx, span := d.tracer.Start(ctx, actionName(query))
	defer span.End()

	result, err := d.base.Handle(ctx, query)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	return result, err
}
