package ws

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/metrics"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// TicketTTL limita por quanto tempo um ticket emitido continua resgatável.
const TicketTTL = 30 * time.Second

// TicketResponse é o corpo retornado por POST /api/v1/ws/ticket.
type TicketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expires_at"`
}

// TicketHandler emite um ticket para o chamador autenticado. Precisa rodar
// atrás de auth.RequireAuthentication.
func TicketHandler(store *TicketStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, ok := auth.IdentityFromContext(r.Context())
		if !ok {
			httputil.WriteError(w, r, logger, apperrors.Unauthorized("authentication required"))
			return
		}

		ticket, err := store.Issue(identity.Subject)
		if err != nil {
			httputil.WriteError(w, r, logger, apperrors.Internal(err))
			return
		}

		httputil.WriteCreated(w, TicketResponse{
			Ticket:    ticket.Value,
			ExpiresAt: ticket.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
}

// UpgradeHandler valida o parâmetro de query ticket, promove a conexão
// para WebSocket e a entrega ao Hub. Diferente de todo outro endpoint,
// este não pode passar por auth.RequireAuthentication (navegadores não
// conseguem anexar um header Authorization ao handshake de WebSocket) — o
// ticket É a autenticação (§38).
func UpgradeHandler(hub *Hub, store *TicketStore, allowedOrigin string, logger *slog.Logger) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// Só aceita o handshake se o Origin bater com o frontend
		// configurado (ou vier vazio, caso de clientes não-browser) —
		// impede que uma página de outro domínio abra WebSockets contra
		// esta API usando um ticket vazado.
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "" || origin == allowedOrigin
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ticketValue := r.URL.Query().Get("ticket")
		if ticketValue == "" {
			http.Error(w, "missing ticket query parameter", http.StatusUnauthorized)
			return
		}

		ticket, err := store.Redeem(ticketValue)
		if err != nil {
			logger.Warn("websocket upgrade rejected", slog.Any("error", err))
			http.Error(w, "invalid or expired ticket", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Error("websocket upgrade failed", slog.Any("error", err))
			metrics.WebSocketErrorsTotal.Inc()
			return
		}

		client := NewClient(hub, conn, ticket.UserID, logger)
		client.Start()
	}
}
