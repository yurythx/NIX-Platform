package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// ZapScannerName é o valor que identifica este CodeScanner no registro
// do scanning.Service.
const ZapScannerName = "zap"

// ZapScanner é o quarto CodeScanner real da plataforma (Fase 6 do
// roadmap de segurança): DAST via um daemon OWASP ZAP self-hosted
// (docker-compose.yml, serviço `zap`) — crawl (spider) seguido de um
// scan ATIVO (ataques de verdade: injeção, XSS, etc.) contra um alvo
// HTTP(S) rodando de verdade.
//
// Diferença fundamental em relação a TrivyScanner/SemgrepScanner/
// SonarScanner: os três primeiros só LEEM código-fonte (nunca
// interagem com o alvo além de clonar/enviar um relatório). O ZAP
// ATIVAMENTE ATACA um serviço rodando de verdade — por isso o alvo aqui
// NUNCA passa por cloneShallow (não é um repositório git, é uma URL
// HTTP onde quer que esteja rodando), e por isso a defesa central deste
// adapter não é a mesma de SSRF dos outros três (IP privado é
// frequentemente o alvo LEGÍTIMO — um ambiente de staging interno), mas
// sim uma ALLOWLIST explícita e obrigatória (SCANNING_ZAP_ALLOWED_HOSTS)
// — regra inegociável do roadmap: ZAP nunca aponta pra produção, e a
// allowlist vazia por padrão recusa todo alvo até um host de
// staging/homologação ser explicitamente autorizado pelo operador.
type ZapScanner struct {
	zapURL       string
	apiKey       string
	allowedHosts map[string]struct{}
	scanTimeout  time.Duration
	httpClient   *http.Client
	logger       *slog.Logger
}

// NewZapScanner constrói o adapter. zapURL vazio é uma configuração
// válida (mesmo princípio de SonarQubeURL) — Execute reporta o scanner
// como indisponível em vez do worker falhar ao inicializar.
func NewZapScanner(zapURL, apiKey string, allowedHosts []string, scanTimeout time.Duration, logger *slog.Logger) *ZapScanner {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		allowed[strings.ToLower(h)] = struct{}{}
	}
	return &ZapScanner{
		zapURL:       strings.TrimRight(zapURL, "/"),
		apiKey:       apiKey,
		allowedHosts: allowed,
		scanTimeout:  scanTimeout,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		logger:       logger,
	}
}

var _ domain.CodeScanner = (*ZapScanner)(nil)

func (z *ZapScanner) Name() string { return ZapScannerName }

// Execute valida o alvo contra a allowlist, roda um spider (crawl) pra
// descobrir a superfície de ataque, depois um scan ativo (os ataques de
// verdade) sobre o que foi descoberto, e por fim busca os alertas
// resultantes. Um scan ativo pode levar de minutos a horas dependendo do
// tamanho do alvo — scanTimeout limita o tempo total (spider + ativo).
func (z *ZapScanner) Execute(ctx context.Context, target string) ([]domain.Finding, error) {
	if z.zapURL == "" {
		return nil, apperrors.DependencyUnavailable("scanning: zap: SCANNING_ZAP_URL is not configured")
	}

	targetURL, err := z.validateTarget(target)
	if err != nil {
		return nil, err
	}

	scanCtx, cancel := context.WithTimeout(ctx, z.scanTimeout)
	defer cancel()

	if err := z.runModule(scanCtx, "spider", targetURL); err != nil {
		return nil, err
	}
	if err := z.runModule(scanCtx, "ascan", targetURL); err != nil {
		return nil, err
	}

	return z.fetchAlerts(ctx, targetURL)
}

// validateTarget exige um alvo http(s) cujo host esteja na allowlist
// configurada — nunca aceita silenciosamente um alvo fora dela, mesmo
// que a allowlist esteja vazia (nesse caso, TODO alvo é recusado, o
// oposto do "aberto por padrão" das outras validações desta plataforma,
// deliberado porque este scanner ataca, não só lê).
func (z *ZapScanner) validateTarget(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", apperrors.Validation(fmt.Sprintf("scanning: zap: invalid target URL: %v", err))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", apperrors.Validation("scanning: zap: target must be an http:// or https:// URL")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", apperrors.Validation("scanning: zap: target URL has no host")
	}
	if len(z.allowedHosts) == 0 {
		return "", apperrors.Validation("scanning: zap: no hosts are allowlisted (SCANNING_ZAP_ALLOWED_HOSTS is empty) — refusing to scan any target")
	}
	if _, ok := z.allowedHosts[host]; !ok {
		return "", apperrors.Validation(fmt.Sprintf("scanning: zap: target host %q is not in the allowlist", host))
	}
	return target, nil
}

// zapActionResponse é a resposta de toda chamada .../action/scan/ — ou
// {"scan":"<id>"} em sucesso, ou {"code":"...","message":"..."} em erro
// (ex.: "url_not_found" se o spider ainda não visitou o alvo antes de um
// scan ativo ser pedido — confirmado contra um daemon real).
type zapActionResponse struct {
	Scan    string `json:"scan"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// zapStatusResponse é a resposta de toda chamada .../view/status/ — o
// progresso vai de "0" a "100" (string, não número — confirmado contra
// o daemon real).
type zapStatusResponse struct {
	Status string `json:"status"`
}

// runModule dispara o módulo (spider ou ascan — os dois compartilham o
// mesmo formato de action/status) contra targetURL e espera terminar
// (status 100).
func (z *ZapScanner) runModule(ctx context.Context, module, targetURL string) error {
	startURL := fmt.Sprintf("%s/JSON/%s/action/scan/?url=%s&apikey=%s",
		z.zapURL, module, url.QueryEscape(targetURL), url.QueryEscape(z.apiKey))

	var action zapActionResponse
	if err := z.getJSON(ctx, startURL, &action); err != nil {
		return err
	}
	if action.Code != "" {
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: zap: %s (%s): %s", module, action.Code, action.Message))
	}

	statusURL := fmt.Sprintf("%s/JSON/%s/view/status/?scanId=%s&apikey=%s",
		z.zapURL, module, url.QueryEscape(action.Scan), url.QueryEscape(z.apiKey))
	for {
		var status zapStatusResponse
		if err := z.getJSON(ctx, statusURL, &status); err != nil {
			return err
		}
		if status.Status == "100" {
			return nil
		}

		select {
		case <-ctx.Done():
			return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: zap: timed out waiting for %s to finish (last progress: %s%%)", module, status.Status))
		case <-time.After(5 * time.Second):
		}
	}
}

// zapAlertsResponse é o subconjunto de GET /JSON/core/view/alerts/ que
// este adapter usa — confirmado contra a saída real de um scan (bem mais
// campos existem na resposta de verdade; só os usados aqui).
type zapAlertsResponse struct {
	Alerts []struct {
		PluginID    string            `json:"pluginId"`
		Risk        string            `json:"risk"`
		Name        string            `json:"name"`
		Description string            `json:"description"`
		URL         string            `json:"url"`
		Tags        map[string]string `json:"tags"`
	} `json:"alerts"`
}

func (z *ZapScanner) fetchAlerts(ctx context.Context, targetURL string) ([]domain.Finding, error) {
	alertsURL := fmt.Sprintf("%s/JSON/core/view/alerts/?baseurl=%s&apikey=%s",
		z.zapURL, url.QueryEscape(targetURL), url.QueryEscape(z.apiKey))

	var resp zapAlertsResponse
	if err := z.getJSON(ctx, alertsURL, &resp); err != nil {
		return nil, err
	}

	findings := make([]domain.Finding, 0, len(resp.Alerts))
	for _, a := range resp.Alerts {
		findings = append(findings, domain.Finding{
			ID:            a.PluginID,
			OWASPCategory: zapOWASPCategory(a.Tags),
			Severity:      normalizeZapRisk(a.Risk),
			Description:   a.Name + ": " + a.Description,
			File:          a.URL,
		})
	}
	return findings, nil
}

// zapOWASPTagPattern casa a chave de tag que o ZAP usa pra marcar um
// alerta como pertencente ao OWASP Top 10 2021 — confirmado contra a
// saída real ("OWASP_2021_A01", valor uma URL como
// "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"). Um mesmo
// alerta pode ter várias tags OWASP (2017, 2021, 2025 simultaneamente,
// visto na saída real) — deliberadamente só a 2021 é usada, pra bater
// com a edição que todo o resto deste roadmap já usa (Trivy/Semgrep
// hardcodam "2021" também).
var zapOWASPTagPattern = regexp.MustCompile(`^OWASP_2021_A\d+$`)

// zapOWASPCategory deriva um rótulo no mesmo formato que
// Trivy/Semgrep já usam ("A01:2021-Broken Access Control") a partir da
// URL da tag OWASP 2021 do alerta — vazio se o alerta não tiver
// nenhuma (mesma convenção de domain.Finding.OWASPCategory pra "não se
// aplica").
func zapOWASPCategory(tags map[string]string) string {
	for key, value := range tags {
		if !zapOWASPTagPattern.MatchString(key) {
			continue
		}
		// value: ".../Top10/A01_2021-Broken_Access_Control/" -> pega o
		// último segmento não vazio do caminho e traduz
		// "A01_2021-Broken_Access_Control" -> "A01:2021-Broken Access Control".
		segments := strings.Split(strings.TrimRight(value, "/"), "/")
		last := segments[len(segments)-1]
		code, rest, ok := strings.Cut(last, "_")
		if !ok {
			return last
		}
		return code + ":" + strings.ReplaceAll(rest, "_", " ")
	}
	return ""
}

// normalizeZapRisk traduz a escala de risco de 4 níveis do ZAP
// (High/Medium/Low/Informational — confirmado contra o daemon real) pra
// domain.Severity. domain.SeverityCritical nunca é usado por este
// scanner — o ZAP não tem uma categoria acima de "High" na própria
// escala dele, mesmo raciocínio que fez o ERROR (nível mais alto) do
// Semgrep virar HIGH, não CRITICAL, em normalizeSemgrepSeverity.
func normalizeZapRisk(risk string) domain.Severity {
	switch strings.ToUpper(risk) {
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	default: // LOW, INFORMATIONAL, ou qualquer valor desconhecido
		return domain.SeverityLow
	}
}

// getJSON busca url e decodifica a resposta JSON em dst — a API do ZAP
// não usa header de autenticação, a apikey vai como query param (ver
// runModule/fetchAlerts), então esta função, ao contrário do equivalente
// em sonar_scanner.go, não define nenhum header extra.
func (z *ZapScanner) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("scanning: zap: build request: %w", err)
	}

	resp, err := z.httpClient.Do(req)
	if err != nil {
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: zap: request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return apperrors.DependencyUnavailable(fmt.Sprintf("scanning: zap: unexpected status %d: %s", resp.StatusCode, firstLine(string(body))))
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("scanning: zap: decode response: %w", err)
	}
	return nil
}
