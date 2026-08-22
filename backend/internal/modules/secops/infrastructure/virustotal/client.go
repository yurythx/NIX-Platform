// Package virustotal implementa domain.SecurityProvider contra a API REST
// v3 real do VirusTotal.
package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/secops/domain"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/internal/platform/resilience"
)

const defaultBaseURL = "https://www.virustotal.com/api/v3"

// providerLabel é o valor deste cliente para o rótulo "provider" em toda
// métrica nix_integration_* (§53).
const providerLabel = "virustotal"

// Client chama a API v3 do VirusTotal. Nunca bloqueia por mais tempo que o
// timeout configurado (§48) e nunca entra em panic por uma API key
// ausente ou uma API inalcançável/com erro — ambos os casos aparecem como
// um erro DependencyUnavailable seguro de mostrar ao cliente. A chamada de
// rede em si roda atrás de um circuit breaker (§ Circuit Breaker &
// Resiliência HTTP): depois de falhas consecutivas, o breaker abre e as
// chamadas passam a falhar rápido com CIRCUIT_OPEN, sem sequer tentar a
// requisição, poupando tanto o VirusTotal quanto a cota de API da chave
// configurada.
type Client struct {
	apiKey  string
	baseURL string
	client  *http.Client
	breaker *resilience.Breaker[*http.Response]
}

// NewClient constrói um Client do VirusTotal, com o timeout e o circuit
// breaker (logger recebe as transições de estado) configurados.
func NewClient(apiKey, baseURL string, timeout time.Duration, logger *slog.Logger) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
		breaker: resilience.New[*http.Response](resilience.Options{Name: providerLabel, Logger: logger}),
	}
}

var _ domain.SecurityProvider = (*Client)(nil)

func (c *Client) Name() string { return "virustotal" }

// TestConnection valida conectividade e a API key requisitando um recurso
// conhecido, estável e inofensivo (o IP do DNS público do Google) — não
// custa cota de análise nem gera nenhum efeito colateral no VirusTotal,
// só confirma que a chave é aceita e a API responde.
func (c *Client) TestConnection(ctx context.Context) error {
	if c.apiKey == "" {
		return apperrors.DependencyUnavailable("VirusTotal API key is not configured").WithCode("INTEGRATION_UNAVAILABLE")
	}

	resp, err := c.do(ctx, "/ip_addresses/8.8.8.8")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := statusToError(resp.StatusCode); err != nil {
		metrics.IntegrationFailuresTotal.WithLabelValues(providerLabel).Inc()
		return err
	}
	return nil
}

// AnalyzeTarget consulta a reputação de um endereço IP. Estender isto
// para domínios/hashes de arquivo/URLs é uma questão de rotear para os
// outros endpoints v3 do VirusTotal de acordo com o formato do target —
// deixado como o próximo incremento natural deste módulo, em vez de
// adivinhado aqui sem um caso de uso concreto que o justifique.
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
		metrics.IntegrationFailuresTotal.WithLabelValues(providerLabel).Inc()
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

	metrics.IntegrationRequestsTotal.WithLabelValues(providerLabel).Inc()
	start := time.Now()
	// O status >= 500 é verificado DENTRO do callback do breaker, não
	// depois — um provedor respondendo consistentemente com erro de
	// servidor deve abrir o circuito tanto quanto uma falha de rede. Um
	// 4xx (ex.: 401 de API key inválida) não conta: é uma resposta HTTP
	// válida que statusToError, chamado por quem invoca do(), interpreta
	// como um erro específico de domínio, não como o provedor fora do ar.
	resp, err := c.breaker.Execute(func() (*http.Response, error) {
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= http.StatusInternalServerError {
			resp.Body.Close()
			return nil, fmt.Errorf("virustotal responded with status %d", resp.StatusCode)
		}
		return resp, nil
	})
	metrics.IntegrationDuration.WithLabelValues(providerLabel).Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.IntegrationFailuresTotal.WithLabelValues(providerLabel).Inc()
		if appErr, ok := apperrors.As(err); ok && appErr.Code == "CIRCUIT_OPEN" {
			return nil, appErr
		}
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("virustotal request failed: %v", err)).WithCode("INTEGRATION_UNAVAILABLE")
	}
	return resp, nil
}

// statusToError mapeia um status HTTP da resposta do VirusTotal para um
// erro de domínio: 401/403 indicam API key rejeitada (mensagem
// específica, para facilitar o diagnóstico); qualquer outro erro
// (4xx/5xx) vira uma indisponibilidade genérica da dependência.
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

// vtIPResponse é o subconjunto da resposta v3 do VirusTotal para
// GET /ip_addresses/{ip} que este cliente de fato usa — o payload real da
// API tem muito mais campos, ignorados aqui deliberadamente.
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
