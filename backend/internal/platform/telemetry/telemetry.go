// Package telemetry configures distributed tracing (§51). If
// OTEL_EXPORTER_OTLP_ENDPOINT is unset, Setup leaves OpenTelemetry's
// default no-op tracer provider in place — the platform never requires a
// collector to be running (none is listed among the docker-compose
// services in §5) — it only exports traces when one is configured.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.42.0"
)

// Shutdown flushes and stops the tracer provider. Safe to call even when
// tracing was never enabled (returns a no-op).
type Shutdown func(context.Context) error

// Setup configures the global tracer provider and text-map propagator.
// serviceName/environment are attached to every span as resource
// attributes. endpoint is the OTLP/HTTP collector address (host:port,
// no scheme) — typically OTEL_EXPORTER_OTLP_ENDPOINT.
func Setup(ctx context.Context, serviceName, environment, endpoint string, logger *slog.Logger) (Shutdown, error) {
	// Every service that talks to another (HTTP client calls, RabbitMQ
	// publish/consume) should propagate trace context the same way,
	// regardless of whether an exporter is configured.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if endpoint == "" {
		logger.Info("telemetry: OTEL_EXPORTER_OTLP_ENDPOINT not set, tracing is a no-op")
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("telemetry: create OTLP exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName(serviceName),
			semconv.DeploymentEnvironmentNameKey.String(environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("telemetry: build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	logger.Info("telemetry: tracing enabled", slog.String("endpoint", endpoint))
	return tp.Shutdown, nil
}
