// Package transport implementa o handler HTTP do módulo diario_oficial
// (§34): validar -> autorizar -> criar job -> 202 Accepted. Nunca chama o
// sistema externo do Diário Oficial diretamente — essa é responsabilidade
// do worker.
package transport

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
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

type testJobResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// TestDiarioOficial trata POST /api/v1/integrations/diario-oficial/test.
// Só cria o job e retorna 202 — o processamento de fato acontece de forma
// assíncrona no worker, e o resultado chega ao frontend via WebSocket.
func (h *Handlers) TestDiarioOficial(w http.ResponseWriter, r *http.Request) {
	correlationID := correlationIDFromRequest(r)

	var requestedBy *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			requestedBy = &id
		}
	}

	job, err := h.service.CreateTestJob(r.Context(), correlationID, requestedBy)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteAccepted(w, testJobResponse{JobID: job.ID.String(), Status: string(job.Status)})
}

// correlationIDFromRequest reaproveita o request id (§50) como o
// correlation id do fluxo de negócio quando ele já é um UUID (sempre é,
// quando gerado por httpserver.RequestID), voltando para um novo UUID caso
// o cliente tenha enviado um valor de X-Request-ID que não é um UUID.
func correlationIDFromRequest(r *http.Request) uuid.UUID {
	if id, err := uuid.Parse(logging.RequestID(r.Context())); err == nil {
		return id
	}
	return uuid.New()
}

// createMonitoredTermRequest é o corpo JSON aceito por POST
// /api/v1/diario-oficial/monitored-terms — espelha domain.MonitoredTerm
// só nos campos que o usuário de fato escolhe (ID/Active/CreatedBy/
// LastSyncedAt/timestamps são responsabilidade do Service, nunca vêm da
// requisição).
type createMonitoredTermRequest struct {
	Label         string `json:"label"`
	OABNumber     string `json:"oab_number"`
	OABState      string `json:"oab_uf"`
	ProcessNumber string `json:"process_number"`
	FreeText      string `json:"free_text"`
}

// CreateMonitoredTerm trata POST /api/v1/diario-oficial/monitored-terms —
// cadastra um termo novo (OAB, número de processo ou texto livre) pra
// acompanhar. Validação de negócio (pelo menos um critério preenchido)
// fica em domain.MonitoredTerm.Validate, chamada por
// application.Service.CreateMonitoredTerm — este handler só decodifica o
// corpo.
func (h *Handlers) CreateMonitoredTerm(w http.ResponseWriter, r *http.Request) {
	var req createMonitoredTermRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	var requestedBy *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			requestedBy = &id
		}
	}

	term := domain.MonitoredTerm{
		Label:         req.Label,
		OABNumber:     req.OABNumber,
		OABState:      req.OABState,
		ProcessNumber: req.ProcessNumber,
		FreeText:      req.FreeText,
	}
	created, err := h.service.CreateMonitoredTerm(r.Context(), term, requestedBy)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteCreated(w, toMonitoredTermResponse(*created))
}

// ListMonitoredTerms trata GET /api/v1/diario-oficial/monitored-terms.
func (h *Handlers) ListMonitoredTerms(w http.ResponseWriter, r *http.Request) {
	terms, err := h.service.ListMonitoredTerms(r.Context())
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	httputil.WriteOK(w, toMonitoredTermResponses(terms))
}

// DeleteMonitoredTerm trata DELETE
// /api/v1/diario-oficial/monitored-terms/{termID}.
func (h *Handlers) DeleteMonitoredTerm(w http.ResponseWriter, r *http.Request) {
	termID, err := uuid.Parse(chi.URLParam(r, "termID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("termID must be a valid UUID"))
		return
	}

	var requestedBy *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			requestedBy = &id
		}
	}

	if err := h.service.DeleteMonitoredTerm(r.Context(), termID, requestedBy); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	// 200 com um envelope vazio, nunca 204 sem corpo — apiClient.delete
	// (frontend) sempre tenta decodificar um Envelope JSON da resposta
	// (ver lib/api/client.ts's request()), mesmo padrão que
	// scanning.UntriageFinding já usa.
	httputil.WriteOK(w, struct{}{})
}

// ListPublicationsForTerm trata GET
// /api/v1/diario-oficial/monitored-terms/{termID}/publications.
func (h *Handlers) ListPublicationsForTerm(w http.ResponseWriter, r *http.Request) {
	termID, err := uuid.Parse(chi.URLParam(r, "termID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("termID must be a valid UUID"))
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	items, meta, err := h.service.ListPublicationsForTerm(r.Context(), termID, page, pageSize)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	httputil.WriteOKWithMeta(w, toMatchedPublicationResponses(items), meta)
}

// ListRecentPublications trata GET /api/v1/diario-oficial/publications —
// o feed agregado entre todo termo monitorado, mais recente primeiro
// (equivalente diario_oficial de scanning's GET /scanning/scans).
func (h *Handlers) ListRecentPublications(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	items, meta, err := h.service.ListRecentMatches(r.Context(), page, pageSize)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	httputil.WriteOKWithMeta(w, toMatchedPublicationResponses(items), meta)
}

// Health trata GET /api/v1/diario-oficial/health — checagem síncrona e
// direta (nunca cria job, nunca grava nada) da fonte de dados
// configurada, pra uma tela mostrar "está respondendo?" antes do usuário
// estranhar por que nenhuma publicação nova apareceu.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	health := h.service.CheckHealth(r.Context())
	httputil.WriteOK(w, toSourceHealthResponse(health))
}

// RateLimitKey limita a criação de jobs por usuário autenticado (§56),
// caindo de volta para o IP remoto se a requisição não estiver autenticada
// (o que não deveria acontecer em condições normais, já que esta rota
// exige autenticação, mas serve de defesa extra).
func RateLimitKey(r *http.Request) string {
	if identity, ok := auth.IdentityFromContext(r.Context()); ok && identity.Subject != "" {
		return identity.Subject
	}
	return httpserver.ClientIPKey(r)
}
