// Package virustotal implements domain.SecurityProvider against the real
// VirusTotal v3 REST API.
package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/secops/domain"
)

const defaultBaseURL = "https://www.virustotal.com/api/v3"

// Client calls the VirusTotal v3 API. It never blocks longer than the
// configured timeout (§48) and never panics on a missing API key or an
// unreachable/erroring API — both surface as a client-safe
// DependencyUnavailable error.
type Client struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

func NewClient(apiKey, baseURL string, timeout time.Duration) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

var _ domain.SecurityProvider = (*Client)(nil)

func (c *Client) Name() string { return "virustotal" }

// TestConnection validates connectivity and API key by requesting a
// known-stable, harmless resource (Google's public DNS IP).
func (c *Client) TestConnection(ctx context.Context) error {
	if c.apiKey == "" {
		return apperrors.DependencyUnavailable("VirusTotal API key is not configured").WithCode("INTEGRATION_UNAVAILABLE")
	}

	resp, err := c.do(ctx, "/ip_addresses/8.8.8.8")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return statusToError(resp.StatusCode)
}

// AnalyzeTarget looks up an IP address's reputation. Extending this to
// domains/file-hashes/URLs is a matter of routing to VirusTotal's other
// v3 endpoints based on the target's shape — left as the module's next
// increment rather than guessed at here.
func (c *Client) AnalyzeTarget(ctx context.Context, target string) (*domain.SecCheckResult, error) {
	if c.apiKey == "" {
		return nil, apperrors.DependencyUnavailable("VirusTotal API key is not configured").WithCode("INTEGRATION_UNAVAILABLE")
	}

	resp, err := c.do(ctx, "/ip_addresses/"+url.PathEscape(target))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := statusToError(resp.StatusCode); err != nil {
		return nil, err
	}

	var parsed vtIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("virustotal: decode response: %w", err)
	}

	stats := parsed.Data.Attributes.LastAnalysisStats
	summary := fmt.Sprintf("%d malicious, %d suspicious, %d harmless (of %d engines)",
		stats.Malicious, stats.Suspicious, stats.Harmless, stats.Malicious+stats.Suspicious+stats.Harmless+stats.Undetected)

	return &domain.SecCheckResult{
		Success: true,
		Summary: summary,
		Details: map[string]any{
			"malicious":  stats.Malicious,
			"suspicious": stats.Suspicious,
			"harmless":   stats.Harmless,
			"undetected": stats.Undetected,
		},
	}, nil
}

func (c *Client) do(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("virustotal: build request: %w", err)
	}
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("virustotal request failed: %v", err)).WithCode("INTEGRATION_UNAVAILABLE")
	}
	return resp, nil
}

func statusToError(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return apperrors.DependencyUnavailable("virustotal rejected the configured API key").WithCode("INTEGRATION_UNAVAILABLE")
	case status >= http.StatusInternalServerError:
		return apperrors.DependencyUnavailable(fmt.Sprintf("virustotal responded with status %d", status)).WithCode("INTEGRATION_UNAVAILABLE")
	case status >= http.StatusBadRequest:
		return apperrors.DependencyUnavailable(fmt.Sprintf("virustotal responded with status %d", status)).WithCode("INTEGRATION_UNAVAILABLE")
	}
	return nil
}

type vtIPResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}
