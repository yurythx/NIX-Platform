// Package httputil provides the standard JSON response envelope, request
// decoding and validation helpers shared by every HTTP transport handler in
// the platform. Handlers must use these instead of writing to
// http.ResponseWriter directly, so every response — success or error — has
// the same {data, error, meta} shape and no handler ever leaks internal
// error detail to a client.
package httputil

import (
	"encoding/json"
	"log/slog"
	"net/http"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/logging"
)

// Envelope is the standard response shape for every NIX Platform endpoint.
type Envelope struct {
	Data  any        `json:"data"`
	Error *ErrorBody `json:"error"`
	Meta  any        `json:"meta,omitempty"`
}

// ErrorBody is the standard error shape. It never contains a stack trace or
// internal error detail — only a stable code and a client-safe message.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteJSON writes a successful envelope with the given HTTP status.
func WriteJSON(w http.ResponseWriter, status int, data any, meta any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Data: data, Error: nil, Meta: meta})
}

// WriteOK writes a 200 OK envelope.
func WriteOK(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusOK, data, nil)
}

// WriteOKWithMeta writes a 200 OK envelope including pagination/other meta.
func WriteOKWithMeta(w http.ResponseWriter, data any, meta any) {
	WriteJSON(w, http.StatusOK, data, meta)
}

// WriteCreated writes a 201 Created envelope.
func WriteCreated(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusCreated, data, nil)
}

// WriteAccepted writes a 202 Accepted envelope — used for async job
// creation endpoints like the Diário Oficial test trigger.
func WriteAccepted(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusAccepted, data, nil)
}

// WriteNoContent writes a 204 No Content response with no body.
func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// WriteError writes the standard error envelope for err. If err is (or
// wraps) an *apperrors.Error its Status/Code/Message are used verbatim;
// otherwise it is treated as an unexpected internal error, logged with its
// full detail server-side, and reported to the client as a generic 500.
func WriteError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	appErr, ok := apperrors.As(err)
	if !ok {
		appErr = apperrors.Internal(err)
	}

	log := logging.FromContext(r.Context(), logger)
	if appErr.Status >= 500 {
		log.Error("request failed", slog.String("code", string(appErr.Code)), slog.Any("error", appErr.Err))
	} else {
		log.Warn("request rejected", slog.String("code", string(appErr.Code)), slog.String("message", appErr.Message))
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(appErr.Status)
	_ = json.NewEncoder(w).Encode(Envelope{
		Data: nil,
		Error: &ErrorBody{
			Code:    string(appErr.Code),
			Message: appErr.Message,
		},
	})
}
