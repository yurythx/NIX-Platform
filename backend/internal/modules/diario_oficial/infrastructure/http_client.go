// Package infrastructure implements the diario_oficial module's external
// dependencies: a real HTTP client against the configured Diário Oficial
// endpoint.
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

// providerLabel is this client's value for the "provider" label on every
// nix_integration_* metric (§53).
const providerLabel = "diario-oficial"

// HTTPClient calls the external Diário Oficial system over HTTP. It never
// blocks longer than the configured timeout (§48) and never panics on a
// missing/unreachable endpoint — both surface as a client-safe
// DependencyUnavailable error instead.
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
