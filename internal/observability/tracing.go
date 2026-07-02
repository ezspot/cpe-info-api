package observability

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// SetupTracing installs an OTLP/HTTP trace pipeline when an OTLP endpoint is
// configured via the standard OTEL_* environment variables; otherwise the
// global no-op tracer stays active and the returned shutdown does nothing.
func SetupTracing(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }

	if strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) == "" &&
		strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) == "" {
		return noop, nil
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return noop, fmt.Errorf("otlp trace exporter: %w", err)
	}

	res := sdkresource.Default()
	if strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")) == "" {
		res, err = sdkresource.Merge(res, sdkresource.NewSchemaless(semconv.ServiceName(serviceName)))
		if err != nil {
			return noop, fmt.Errorf("otel resource: %w", err)
		}
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return provider.Shutdown, nil
}
