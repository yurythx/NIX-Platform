package transport

import (
	"log/slog"

	"github.com/go-chi/chi/v5"

	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
)

// RegisterRoutes mounts the scanning module's routes onto an already
// auth.RequireAuthentication-protected router. scanLimiter/
// projectLimiter are built once in internal/app (backed by Postgres,
// shared across every API replica) and passed in rather than constructed
// here, so every module doesn't stand up its own store — two SEPARATE
// instances, not one reused for both routes: clonar+escanear
// (scanLimiter) custa bem mais que criar um registro de projeto
// (projectLimiter), então cada um tem seu próprio orçamento (ver
// internal/app/dependencies.go's RateLimiters.ScanJob/ProjectCreate).
func RegisterRoutes(r chi.Router, h *Handlers, logger *slog.Logger, scanLimiter, projectLimiter httpserver.Limiter) {
	r.With(
		auth.RequirePermission(logger, auth.PermScanningManage),
		httpserver.RateLimit(logger, scanLimiter, RateLimitKey),
	).Post("/scanning/scans", h.CreateScan)

	// Revisão de exibição de resultados: a tela "saúde das ferramentas"
	// antes de disparar um scan — scanning:read, mesma permissão de
	// qualquer outra leitura deste módulo (não dispara nada, só
	// consulta).
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/scanners/health", h.ScannersHealth)

	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/scans", h.ListScans)

	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/scans/{scanID}", h.GetScanStatus)

	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/scans/{scanID}/findings", h.ListFindings)

	// Fase 14 (Maturidade de AppSec): o mesmo achado, em CSV — pra levar
	// pra fora da plataforma (planilha, ticket, anexo de auditoria).
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/scans/{scanID}/findings.csv", h.ExportFindings)

	// SARIF (shift-left) — o mesmo achado, no formato que GitHub Code
	// Scanning/Azure DevOps consomem nativamente, virando anotação no
	// diff do PR sem esta plataforma construir UI de comentário própria.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/scans/{scanID}/findings.sarif", h.ExportFindingsSarif)

	// Fase 11 (Syft): inventário de pacotes de uma execução — nunca acha
	// nada, então nunca aparece em .../findings; rota própria, mesmo
	// scanID.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/scans/{scanID}/packages", h.ListPackages)

	// Fase 9 (UI no frontend): achados recentes entre TODOS os scans, não
	// escopados a um scan_id — o feed que a UI usa pra listar sem exigir
	// conhecer um scan_id de antemão.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/findings", h.ListRecentFindings)

	// Fase 10 — Projeto como entidade própria + upload .zip. Criar um
	// projeto é scanning:manage (a mesma permissão que já exige disparar
	// um scan avulso); listar é scanning:read, mesmo princípio do resto
	// deste módulo.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningManage),
		httpserver.RateLimit(logger, projectLimiter, RateLimitKey),
	).Post("/scanning/projects", h.CreateProject)

	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/projects", h.ListProjects)

	// Fase 12 (deduplicação por fingerprint): histórico deduplicado de
	// achados ENTRE os scans de um projeto.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/projects/{projectID}/findings-history", h.ListProjectFindingsHistory)

	// Fase 14 (Maturidade de AppSec): o mesmo histórico deduplicado, em CSV.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/projects/{projectID}/findings-history.csv", h.ExportProjectFindingsHistory)

	// Fase 14 (Maturidade de AppSec): triar (PUT) ou reabrir (DELETE) um
	// achado deduplicado — scanning:manage, a mesma permissão que já
	// exige disparar um scan/criar um projeto: suprimir um achado é uma
	// decisão de mesmo peso, não uma simples leitura.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningManage),
	).Put("/scanning/projects/{projectID}/findings/{fingerprint}/triage", h.TriageFinding)

	r.With(
		auth.RequirePermission(logger, auth.PermScanningManage),
	).Delete("/scanning/projects/{projectID}/findings/{fingerprint}/triage", h.UntriageFinding)

	// Fase 14 (Maturidade de AppSec): resumo agregado pro card de postura
	// de segurança do dashboard — scanning:read, mesma permissão de
	// qualquer outra listagem deste módulo.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/posture", h.SecurityPosture)

	// Fase 14, continuação (tendência histórica): a série temporal por
	// trás do gráfico de tendência do dashboard.
	r.With(
		auth.RequirePermission(logger, auth.PermScanningRead),
	).Get("/scanning/posture/history", h.PostureHistory)
}
