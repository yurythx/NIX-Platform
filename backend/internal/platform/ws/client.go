package ws

import (
	"log/slog"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10 // precisa ser menor que pongWait
	maxMessage = 4096                // clientes nunca nos enviam payloads com significado
)

// Client é uma aba de navegador conectada via WebSocket, identificada pelo
// subject do Keycloak que resgatou o ticket usado para abri-la.
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	userID string
	logger *slog.Logger
}

// NewClient envolve uma conexão já promovida (upgraded) para WebSocket.
func NewClient(hub *Hub, conn *websocket.Conn, userID string, logger *slog.Logger) *Client {
	return &Client{
		hub:    hub,
		conn:   conn,
		send:   make(chan []byte, 16),
		userID: userID,
		logger: logger,
	}
}

// Start registra o cliente no hub e inicia suas bombas de leitura/escrita
// (read/write pumps). Retorna quando ambas as bombas terminarem (ou seja,
// a conexão está totalmente fechada).
func (c *Client) Start() {
	c.hub.Register(c)

	done := make(chan struct{})
	go func() {
		c.writePump()
		close(done)
	}()
	c.readPump()
	<-done
}

// readPump só existe para detectar o fechamento da conexão e para manter
// o handler de pong plugado, viabilizando o heartbeat (§39) — a plataforma
// nunca espera mensagens de aplicação com significado vindas do navegador
// nesta conexão (o WebSocket aqui é só de saída, servidor -> cliente).
func (c *Client) readPump() {
	defer c.hub.Unregister(c)

	c.conn.SetReadLimit(maxMessage)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			return
		}
	}
}

// writePump entrega as mensagens de broadcast e os pings periódicos,
// fechando a conexão se uma escrita falhar ou se o hub fechar c.send
// (sinal de que o cliente foi removido do Hub).
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
