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

// TicketTTL bounds how long an issued ticket remains redeemable.
const TicketTTL = 30 * time.Second

// TicketResponse is the body returned by POST /api/v1/ws/ticket.
type TicketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expires_at"`
}

// TicketHandler issues a ticket for the authenticated caller. Must run
// behind auth.RequireAuthentication.
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

// UpgradeHandler validates the ticket query parameter, upgrades the
// connection, and hands it to the Hub. Unlike every other endpoint, this
// one cannot go through auth.RequireAuthentication (browsers can't attach
// an Authorization header to a WebSocket handshake) — the ticket IS the
// authentication (§38).
func UpgradeHandler(hub *Hub, store *TicketStore, allowedOrigin string, logger *slog.Logger) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
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
