package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/time/rate"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

const RequestIDHeader = "X-Request-ID"

// RequestID honors an inbound X-Request-ID header or generates one,
// echoes it back on the response, and stores it in the request context so
// every log line and downstream call (DB, outbox, RabbitMQ) can carry it.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := logging.WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AccessLog logs one structured line per request with method, path,
// status, duration and request id.
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)

			logging.FromContext(r.Context(), logger).Info("http_request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.status),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Metrics records nix_http_requests_total and nix_http_request_duration_seconds
// (§53). It labels by chi's matched route *pattern* (e.g. "/api/v1/users/{id}"),
// read from the routing context after ServeHTTP returns — never the raw
// path, which would blow up cardinality with one series per user id.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)

		route := "unmatched"
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			if pattern := rctx.RoutePattern(); pattern != "" {
				route = pattern
			}
		}

		metrics.HTTPRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(ww.status)).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

// Recoverer converts a panic in any downstream handler into a structured
// 500 response instead of crashing the process or leaking a stack trace.
func Recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logging.FromContext(r.Context(), logger).Error("panic recovered",
						slog.Any("panic", rec),
						slog.String("path", r.URL.Path),
					)
					httputil.WriteError(w, r, logger, apperrors.Internal(fmt.Errorf("panic: %v", rec)))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets the baseline security headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// clientLimiter is a per-key token bucket limiter with lazy eviction of
// stale entries. It is intentionally in-memory/single-instance — the
// platform has no Redis by design (§7); a multi-instance deployment should
// front the API with an infrastructure-level rate limiter instead.
type clientLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateEntry
	rps      rate.Limit
	burst    int
}

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newClientLimiter(rps float64, burst int) *clientLimiter {
	cl := &clientLimiter{
		limiters: make(map[string]*rateEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
	go cl.evictLoop()
	return cl
}

func (cl *clientLimiter) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cl.mu.Lock()
		for key, entry := range cl.limiters {
			if time.Since(entry.lastSeen) > 10*time.Minute {
				delete(cl.limiters, key)
			}
		}
		cl.mu.Unlock()
	}
}

func (cl *clientLimiter) allow(key string) bool {
	cl.mu.Lock()
	entry, ok := cl.limiters[key]
	if !ok {
		entry = &rateEntry{limiter: rate.NewLimiter(cl.rps, cl.burst)}
		cl.limiters[key] = entry
	}
	entry.lastSeen = time.Now()
	limiter := entry.limiter
	cl.mu.Unlock()

	return limiter.Allow()
}

// RateLimit returns a middleware limiting each client (identified by
// keyFunc, typically the authenticated user id or remote IP) to rps
// requests/second with the given burst.
func RateLimit(logger *slog.Logger, rps float64, burst int, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	cl := newClientLimiter(rps, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			if !cl.allow(key) {
				httputil.WriteError(w, r, logger, apperrors.RateLimited("too many requests, please try again later"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIPKey is a default keyFunc for RateLimit using RemoteAddr.
func ClientIPKey(r *http.Request) string {
	return r.RemoteAddr
}

// contextTimeout is a small helper used by readiness checks.
func contextTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
