// Package transport implements the secops module's HTTP handlers.
package transport

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/modules/secops/application"
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

// TestVirusTotal handles POST /api/v1/integrations/secops/virustotal/test.
func (h *Handlers) TestVirusTotal(w http.ResponseWriter, r *http.Request) {
	h.createTestJob(w, r, "virustotal")
}

func (h *Handlers) createTestJob(w http.ResponseWriter, r *http.Request, providerKey string) {
	correlationID := correlationIDFromRequest(r)

	var requestedBy *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			requestedBy = &id
		}
	}

	job, err := h.service.CreateTestJob(r.Context(), providerKey, correlationID, requestedBy)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteAccepted(w, testJobResponse{JobID: job.ID.String(), Status: string(job.Status)})
}

func correlationIDFromRequest(r *http.Request) uuid.UUID {
	if id, err := uuid.Parse(logging.RequestID(r.Context())); err == nil {
		return id
	}
	return uuid.New()
}

// RateLimitKey rate-limits job creation per authenticated user (§56).
func RateLimitKey(r *http.Request) string {
	if identity, ok := auth.IdentityFromContext(r.Context()); ok && identity.Subject != "" {
		return identity.Subject
	}
	return httpserver.ClientIPKey(r)
}
