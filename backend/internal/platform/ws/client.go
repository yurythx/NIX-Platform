package ws

import (
	"log/slog"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10 // must be less than pongWait
	maxMessage = 4096                // clients never send meaningful payloads to us
)

// Client is one connected WebSocket browser tab, identified by the
// Keycloak subject that redeemed the ticket used to open it.
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	userID string
	logger *slog.Logger
}

// NewClient wraps an already-upgraded connection.
func NewClient(hub *Hub, conn *websocket.Conn, userID string, logger *slog.Logger) *Client {
	return &Client{
		hub:    hub,
		conn:   conn,
		send:   make(chan []byte, 16),
		userID: userID,
		logger: logger,
	}
}

// Start registers the client and launches its read/write pumps. Returns
// once both pumps have exited (i.e. the connection is fully closed).
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

// readPump only exists to detect the connection closing and to keep the
// pong handler wired up for heartbeat (§39) — the platform never expects
// meaningful application messages from the browser on this connection.
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

// writePump delivers broadcast messages and periodic pings, closing the
// connection if a write fails or the hub closes c.send.
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
