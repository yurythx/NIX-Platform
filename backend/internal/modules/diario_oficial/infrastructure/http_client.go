// Package infrastructure implementa as dependências externas do módulo
// diario_oficial: um cliente HTTP real contra o endpoint configurado do
// Diário Oficial.
package infrastructure

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/internal/platform/resilience"
)

// providerLabel é o valor deste cliente para o rótulo "provider" em toda
// métrica nix_integration_* (§53).
const providerLabel = "diario-oficial"

// HTTPClient chama o sistema externo do Diário Oficial via HTTP. Nunca
// bloqueia por mais tempo que o timeout configurado (§48) e nunca entra em
// panic por um endpoint ausente/inalcançável — ambos os casos aparecem
// como um erro DependencyUnavailable seguro de mostrar ao cliente, em vez
// disso. A chamada de rede em si roda atrás de um circuit breaker (§
// Circuit Breaker & Resiliência HTTP): depois de falhas consecutivas, o
// breaker abre e Check passa a falhar rápido com CIRCUIT_OPEN, sem sequer
// tentar a requisição, até o Diário Oficial mostrar sinal de vida de novo.
type HTTPClient struct {
	baseURL string
	client  *http.Client
	breaker *resilience.Breaker[*http.Response]
}

// NewHTTPClient constrói um HTTPClient contra baseURL, com o timeout e o
// circuit breaker (logger recebe as transições de estado) configurados.
func NewHTTPClient(baseURL string, timeout time.Duration, logger *slog.Logger) *HTTPClient {
	return &HTTPClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
		breaker: resilience.New[*http.Response](resilience.Options{Name: providerLabel, Logger: logger}),
	}
}

var _ domain.Client = (*HTTPClient)(nil)

func (c *HTTPClient) Check(ctx context.Context) (*domain.CheckResult, error) {
	// Um ambiente sem DIARIO_OFICIAL_BASE_URL configurada deve reportar a
	// integração como indisponível de forma previsível, não tentar uma
	// requisição HTTP para uma URL vazia e falhar de um jeito confuso.
	if c.baseURL == "" {
		return nil, apperrors.DependencyUnavailable("Diário Oficial integration is not configured").WithCode("INTEGRATION_UNAVAILABLE")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: build request: %w", err)
	}

	metrics.IntegrationRequestsTotal.WithLabelValues(providerLabel).Inc()
	start := time.Now()
	// O status >= 500 é verificado DENTRO do callback do breaker, não
	// depois — assim tanto uma falha de rede quanto um provedor
	// respondendo consistentemente com erro de servidor contam como
	// falha para o circuit breaker. Um 4xx (ex.: 404) não conta: é uma
	// resposta HTTP válida, só não a que se esperava, e não é sinal de
	// que o provedor está indisponível.
	resp, err := c.breaker.Execute(func() (*http.Response, error) {
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= http.StatusInternalServerError {
			resp.Body.Close()
			return nil, fmt.Errorf("diario oficial responded with status %d", resp.StatusCode)
		}
		return resp, nil
	})
	metrics.IntegrationDuration.WithLabelValues(providerLabel).Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.IntegrationFailuresTotal.WithLabelValues(providerLabel).Inc()
		if appErr, ok := apperrors.As(err); ok && appErr.Code == "CIRCUIT_OPEN" {
			// Já é um erro de domínio pronto para o cliente — repassa
			// como está, sem envolver numa mensagem genérica de mais.
			return nil, appErr
		}
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("diario oficial request failed: %v", err)).WithCode("INTEGRATION_UNAVAILABLE")
	}
	defer resp.Body.Close()

	return &domain.CheckResult{
		StatusCode: resp.StatusCode,
		Summary:    fmt.Sprintf("responded with HTTP %d", resp.StatusCode),
	}, nil
}
