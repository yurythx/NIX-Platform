package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/yurythx/nix-platform/pkg/httputil"
)

// Check é uma verificação de dependência de readiness (ex.: "postgres",
// "rabbitmq") — um nome para exibir no relatório e a função que
// efetivamente testa se a dependência está alcançável.
type Check struct {
	Name string
	Fn   func(ctx context.Context) error
}

// HealthHandler responde à sonda de liveness: o processo está de pé e
// consegue atender requisições HTTP. Nunca verifica dependências externas
// — essa é a responsabilidade do /ready — para que uma dependência com
// problema (ex.: Postgres fora do ar) não faça um orquestrador (Kubernetes,
// Docker Swarm) matar o processo via probe de liveness quando na verdade
// o processo em si está saudável (§54).
func HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteOK(w, map[string]string{"status": "ok"})
	}
}

// ReadyHandler verifica cada dependência essencial (PostgreSQL, RabbitMQ)
// com o timeout por verificação informado, e reporta 200 somente se todas
// tiverem sucesso — 503 caso contrário. Usado por um orquestrador para
// decidir se deve rotear tráfego para esta instância.
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
