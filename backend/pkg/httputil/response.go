// Package httputil fornece o envelope de resposta JSON padrão, a
// decodificação de requisição e os helpers de validação compartilhados
// por todo handler de transporte HTTP da plataforma. Handlers devem usar
// estes helpers em vez de escrever direto em http.ResponseWriter, para que
// toda resposta — sucesso ou erro — tenha o mesmo formato {data, error,
// meta} e nenhum handler acabe vazando detalhe de erro interno para o
// cliente.
package httputil

import (
	"encoding/json"
	"log/slog"
	"net/http"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/logging"
)

// Envelope é o formato de resposta padrão de todo endpoint do NIX Platform.
type Envelope struct {
	Data  any        `json:"data"`
	Error *ErrorBody `json:"error"`
	Meta  any        `json:"meta,omitempty"`
}

// ErrorBody é o formato de erro padrão. Nunca contém stack trace ou
// detalhe de erro interno — só um código estável e uma mensagem segura de
// mostrar ao cliente.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteJSON escreve um envelope de sucesso com o status HTTP informado.
func WriteJSON(w http.ResponseWriter, status int, data any, meta any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Data: data, Error: nil, Meta: meta})
}

// WriteOK escreve um envelope 200 OK.
func WriteOK(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusOK, data, nil)
}

// WriteOKWithMeta escreve um envelope 200 OK incluindo metadados de
// paginação/outros.
func WriteOKWithMeta(w http.ResponseWriter, data any, meta any) {
	WriteJSON(w, http.StatusOK, data, meta)
}

// WriteCreated escreve um envelope 201 Created.
func WriteCreated(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusCreated, data, nil)
}

// WriteAccepted escreve um envelope 202 Accepted — usado pelos endpoints
// de criação de job assíncrono, como o gatilho de teste do Diário Oficial.
func WriteAccepted(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusAccepted, data, nil)
}

// WriteNoContent escreve uma resposta 204 No Content sem corpo.
func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// WriteError escreve o envelope de erro padrão para err. Se err for (ou
// envolver) um *apperrors.Error, seu Status/Code/Message são usados tal
// qual; caso contrário, é tratado como um erro interno inesperado, logado
// com todo o detalhe no lado do servidor, e reportado ao cliente como um
// 500 genérico — o cliente nunca vê o erro bruto original nesse caso.
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
