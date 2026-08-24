// Package transport implementa os handlers HTTP do módulo scanning:
// disparar um scan assíncrono (POST) e consultar seus achados (GET). Nunca
// executa um CodeScanner diretamente — CreateScanJob só cria o job e seu
// evento de outbox disparador; a execução de fato acontece no worker (ver
// scanning/worker), rodando todo scanner pedido em paralelo (Fase 7 —
// Orquestração concorrente).
package transport

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/application"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

type Handlers struct {
	service *application.Service
	logger  *slog.Logger
}

func NewHandlers(service *application.Service, logger *slog.Logger) *Handlers {
	return &Handlers{service: service, logger: logger}
}

// createScanRequest aceita um ou mais scanners — mais de um dispara todos
// em paralelo contra o mesmo alvo, sob o mesmo job/scan_id (Fase 7).
type createScanRequest struct {
	Scanners []string `json:"scanners"`
	Target   string   `json:"target"`
}

type scanJobResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// CreateScan trata POST /api/v1/scanning/scans. Só cria o job e retorna
// 202 — o clone/scan de fato acontece de forma assíncrona no worker, e o
// resultado chega ao frontend via WebSocket (scanning.scan.completed /
// scanning.scan.failed). job_id retornado aqui é o mesmo scan_id usado
// depois em GET .../scans/{scan_id}/findings.
func (h *Handlers) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	correlationID := correlationIDFromRequest(r)

	var requestedBy *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			requestedBy = &id
		}
	}

	job, err := h.service.CreateScanJob(r.Context(), correlationID, req.Scanners, req.Target, requestedBy)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteAccepted(w, scanJobResponse{JobID: job.ID.String(), Status: string(job.Status)})
}

// ListFindings trata GET /api/v1/scanning/scans/{scanID}/findings.
func (h *Handlers) ListFindings(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "scanID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("scanID must be a valid UUID"))
		return
	}

	findings, err := h.service.ListFindings(r.Context(), scanID)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toFindingResponses(findings))
}

// GetScanStatus trata GET /api/v1/scanning/scans/{scanID} — pensado pra
// UI fazer polling logo depois de CreateScan até o status virar terminal
// (completed/failed/dead_letter), e então mostrar não só os achados
// (ListFindings) mas também qual scanner falhou, de que tipo foi o erro
// e como corrigir (ver ScanStatusResponse/remediationHint) — resposta
// direta ao pedido do usuário de saber "qual ferramenta achou o erro" e
// separar os erros por tipo/correção, que antes só existia no log do
// worker.
func (h *Handlers) GetScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "scanID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("scanID must be a valid UUID"))
		return
	}

	status, err := h.service.GetScanStatus(r.Context(), scanID)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toScanStatusResponse(status))
}

// ListRecentFindings trata GET /api/v1/scanning/findings — o feed "achados
// recentes por severidade" (Fase 9) usado pela UI, que não exige um
// scan_id de antemão como ListFindings exige.
func (h *Handlers) ListRecentFindings(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	findings, err := h.service.ListRecentFindings(r.Context(), limit)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toFindingResponses(findings))
}

// correlationIDFromRequest reaproveita o request id (§50) como o
// correlation id do fluxo de negócio quando ele já é um UUID, voltando
// para um novo UUID caso o cliente tenha enviado um X-Request-ID que não
// é um UUID — mesmo padrão de diario_oficial/transport/handlers.go.
func correlationIDFromRequest(r *http.Request) uuid.UUID {
	if id, err := uuid.Parse(logging.RequestID(r.Context())); err == nil {
		return id
	}
	return uuid.New()
}

// RateLimitKey limita a criação de scans por usuário autenticado, caindo
// de volta para o IP remoto se a requisição não estiver autenticada (não
// deveria acontecer nesta rota, que exige autenticação, mas serve de
// defesa extra) — mesmo padrão de diario_oficial.
func RateLimitKey(r *http.Request) string {
	if identity, ok := auth.IdentityFromContext(r.Context()); ok && identity.Subject != "" {
		return identity.Subject
	}
	return httpserver.ClientIPKey(r)
}
