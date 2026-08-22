// Package logging configures the application's structured logger (log/slog).
// It never logs secrets: callers must not pass tokens, passwords or client
// secrets as log attributes.
package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

type ctxKey string

const (
	requestIDKey     ctxKey = "request_id"
	correlationIDKey ctxKey = "correlation_id"
	userIDKey        ctxKey = "user_id"
)

// Options configures the base logger.
type Options struct {
	Level       string // debug | info | warn | error
	Format      string // json | text
	Service     string
	Environment string
}

// New builds a slog.Logger writing to stdout in the requested format and
// level, with service/environment attributes attached to every record.
func New(opts Options) *slog.Logger {
	level := parseLevel(opts.Level)

	handlerOpts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.EqualFold(opts.Format, "text") {
		handler = slog.NewTextHandler(os.Stdout, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	}

	logger := slog.New(handler).With(
		slog.String("service", opts.Service),
		slog.String("environment", opts.Environment),
	)

	return logger
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithRequestID returns a context carrying the given HTTP request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID extracts the request id previously stored via WithRequestID.
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// WithCorrelationID returns a context carrying the given correlation id,
// used to trace a single business flow across HTTP, Postgres, RabbitMQ,
// the worker and WebSocket notifications.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

// CorrelationID extracts the correlation id previously stored via
// WithCorrelationID.
func CorrelationID(ctx context.Context) string {
	v, _ := ctx.Value(correlationIDKey).(string)
	return v
}

// WithUserID returns a context carrying the authenticated user's id.
func WithUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// UserID extracts the user id previously stored via WithUserID.
func UserID(ctx context.Context) string {
	v, _ := ctx.Value(userIDKey).(string)
	return v
}

// FromContext returns a logger enriched with request_id/correlation_id/
// user_id attributes pulled from ctx, when present. Handlers and use cases
// should call this instead of logging with the bare base logger so every
// log line can be correlated to a single request/flow.
func FromContext(ctx context.Context, base *slog.Logger) *slog.Logger {
	l := base
	if id := RequestID(ctx); id != "" {
		l = l.With(slog.String("request_id", id))
	}
	if id := CorrelationID(ctx); id != "" {
		l = l.With(slog.String("correlation_id", id))
	}
	if id := UserID(ctx); id != "" {
		l = l.With(slog.String("user_id", id))
	}
	return l
}
