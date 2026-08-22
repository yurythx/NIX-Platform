// Package ws implementa o transporte de notificações via WebSocket da
// plataforma: um Hub de conexões sem nenhuma regra de negócio (§37),
// tickets de uso único e curta duração para autenticação em vez de um
// token na URL (§38), e a metade do lado servidor do suporte a reconexão
// (heartbeat/ping).
package ws

import (
	"context"
	"log/slog"
	"sync"

	"github.com/yurythx/nix-platform/internal/platform/metrics"
)

// Hub rastreia todo cliente conectado e distribui (fan-out) as mensagens
// de broadcast para todos eles. Nunca inspeciona o conteúdo da mensagem —
// isso é responsabilidade do consumer de notificação (internal/app conecta
// um consumer do RabbitMQ que chama Broadcast com o envelope JSON bruto de
// cada evento).
type Hub struct {
	logger *slog.Logger

	mu      sync.RWMutex
	clients map[*Client]struct{}

	register   chan *Client
	unregister chan *Client
	broadcast  chan []byte
	done       chan struct{}
}

// NewHub constrói um Hub ocioso. Chame Run para iniciar seu loop de
// eventos.
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

// Run processa registros e broadcasts até ctx ser cancelado, e então fecha
// o canal de envio de todo cliente conectado e retorna.
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
			metrics.WebSocketConnections.Set(float64(count))
			h.logger.Info("websocket client connected", slog.String("user_id", c.userID), slog.Int("total_clients", count))

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
			count := len(h.clients)
			h.mu.Unlock()
			metrics.WebSocketConnections.Set(float64(count))
			h.logger.Info("websocket client disconnected", slog.String("user_id", c.userID), slog.Int("total_clients", count))

		case msg := <-h.broadcast:
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					// Cliente lento/travado: descarta em vez de deixar um
					// retardatário bloquear a entrega para todos os
					// outros — o canal c.send tem buffer limitado, e um
					// send que bloquearia trava o loop inteiro do Hub.
					h.logger.Warn("dropping slow websocket client", slog.String("user_id", c.userID))
					metrics.WebSocketErrorsTotal.Inc()
					go h.Unregister(c)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Register adiciona um cliente ao hub. Seguro de chamar concorrentemente.
// Vira no-op se o hub já foi encerrado.
func (h *Hub) Register(c *Client) {
	select {
	case h.register <- c:
	case <-h.done:
	}
}

// Unregister remove um cliente do hub. Seguro de chamar concorrentemente,
// mais de uma vez para o mesmo cliente, e depois que o hub já foi
// encerrado.
func (h *Hub) Unregister(c *Client) {
	select {
	case h.unregister <- c:
	case <-h.done:
	}
}

// Broadcast entrega msg (um envelope de evento em JSON bruto) para todo
// cliente conectado. O schema de evento (posse do job/integração) hoje não
// restringe notificações a um único usuário, então todo cliente
// autenticado vê toda notificação da plataforma — ver ClientCount como
// ponto de extensão caso um módulo futuro precise de segmentação por
// usuário.
func (h *Hub) Broadcast(msg []byte) {
	h.broadcast <- msg
}

// ClientCount reporta quantos clientes estão conectados no momento,
// exposto para a visão de status do sistema no dashboard.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
