// Package infrastructure implementa as dependências externas do módulo
// diario_oficial: um cliente HTTP real contra o endpoint configurado do
// Diário Oficial.
package infrastructure

import (
	"context"
	"fmt"
	"net/http"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
)

// providerLabel é o valor deste cliente para o rótulo "provider" em toda
// métrica nix_integration_* (§53).
const providerLabel = "diario-oficial"

// HTTPClient chama o sistema externo do Diário Oficial via HTTP. Nunca
// bloqueia por mais tempo que o timeout configurado (§48) e nunca entra em
// panic por um endpoint ausente/inalcançável — ambos os casos aparecem
// como um erro DependencyUnavailable seguro de mostrar ao cliente, em vez
// disso.
type HTTPClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPClient(baseURL string, timeout time.Duration) *HTTPClient {
	return &HTTPClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
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
	resp, err := c.client.Do(req)
	metrics.IntegrationDuration.WithLabelValues(providerLabel).Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.IntegrationFailuresTotal.WithLabelValues(providerLabel).Inc()
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("diario oficial request failed: %v", err)).WithCode("INTEGRATION_UNAVAILABLE")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError {
		metrics.IntegrationFailuresTotal.WithLabelValues(providerLabel).Inc()
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("diario oficial responded with status %d", resp.StatusCode)).WithCode("INTEGRATION_UNAVAILABLE")
	}

	return &domain.CheckResult{
		StatusCode: resp.StatusCode,
		Summary:    fmt.Sprintf("responded with HTTP %d", resp.StatusCode),
	}, nil
}
