// Package transport implementa o handler HTTP do módulo diario_oficial
// (§34): validar -> autorizar -> criar job -> 202 Accepted. Nunca chama o
// sistema externo do Diário Oficial diretamente — essa é responsabilidade
// do worker.
package transport

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/application"
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
