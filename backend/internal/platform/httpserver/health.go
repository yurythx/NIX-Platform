package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/yurythx/nix-platform/pkg/httputil"
)

// Check is one readiness dependency check (e.g. "postgres", "rabbitmq").
type Check struct {
	Name string
	Fn   func(ctx context.Context) error
}

// HealthHandler answers liveness: the process is up and able to handle
// HTTP requests. It never checks external dependencies — that is /ready's
// job — so a struggling dependency doesn't get the process killed by an
// orchestrator's liveness probe.
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteOK(w, map[string]string{"status": "ok"})
	}
}

// ReadyHandler checks every essential dependency (PostgreSQL, RabbitMQ)
// with the given per-check timeout and reports 200 only if all succeed,
// 503 otherwise.
func ReadyHandler(checks []Check, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		results := make(map[string]string, len(checks))
		ready := true

		for _, c := range checks {
			ctx, cancel := contextTimeout(r.Context(), timeout)
			err := c.Fn(ctx)
			cancel()

			if err != nil {
				results[c.Name] = "unavailable"
				ready = false
				continue
			}
			results[c.Name] = "ok"
		}

		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		httputil.WriteJSON(w, status, results, nil)
	}
}
