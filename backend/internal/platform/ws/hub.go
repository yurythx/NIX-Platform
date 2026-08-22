// Package ws implements the platform's WebSocket notification transport:
// a connection Hub with no business logic (§37), short-lived single-use
// tickets for authentication instead of a token in the URL (§38), and the
// server-side half of reconnection support (heartbeat pings).
package ws

import (
	"context"
	"log/slog"
	"sync"
)

// Hub tracks every connected client and fans out broadcast messages to
// all of them. It never inspects message content — that's the notification
// consumer's job (internal/app wires a RabbitMQ consumer that calls
// Broadcast with each event's raw JSON envelope).
type Hub struct {
	logger *slog.Logger

	mu      sync.RWMutex
	clients map[*Client]struct{}

	register   chan *Client
	unregister chan *Client
	broadcast  chan []byte
	done       chan struct{}
}

// NewHub builds an idle Hub. Call Run to start its event loop.
func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		logger:     logger,
		clients:    make(map[*Client]struct{}),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan []byte, 64),
		done:       make(chan struct{}),
	}
}

// Run processes registrations and broadcasts until ctx is cancelled, then
// closes every connected client's send channel and returns.
func (h *Hub) Run(ctx context.Context) error {
	defer close(h.done)
	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for c := range h.clients {
				close(c.send)
			}
			h.clients = make(map[*Client]struct{})
			h.mu.Unlock()
			return nil

		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = struct{}{}
			count := len(h.clients)
			h.mu.Unlock()
			h.logger.Info("websocket client connected", slog.String("user_id", c.userID), slog.Int("total_clients", count))

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
			count := len(h.clients)
			h.mu.Unlock()
			h.logger.Info("websocket client disconnected", slog.String("user_id", c.userID), slog.Int("total_clients", count))

		case msg := <-h.broadcast:
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					// Slow/stuck client: drop it rather than let one
					// laggard block delivery to everyone else.
					h.logger.Warn("dropping slow websocket client", slog.String("user_id", c.userID))
					go h.Unregister(c)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Register adds a client to the hub. Safe to call concurrently. A no-op if
// the hub has already shut down.
func (h *Hub) Register(c *Client) {
	select {
	case h.register <- c:
	case <-h.done:
	}
}

// Unregister removes a client from the hub. Safe to call concurrently,
// more than once for the same client, and after the hub has shut down.
func (h *Hub) Unregister(c *Client) {
	select {
	case h.unregister <- c:
	case <-h.done:
	}
}

// Broadcast delivers msg (a raw JSON event envelope) to every connected
// client. The schema's fields (job/integration ownership) don't currently
// scope notifications to a single user, so every authenticated client sees
// every platform notification — see ClientCount for the extension point if
// a future module needs per-user targeting.
func (h *Hub) Broadcast(msg []byte) {
	h.broadcast <- msg
}

// ClientCount reports how many clients are currently connected, exposed
// for the dashboard's system-status view.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
