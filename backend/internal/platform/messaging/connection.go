// Package messaging implements the RabbitMQ adapter for the platform's
// events.EventPublisher/EventConsumer abstractions: a topic exchange
// (nix.events), per-module durable queues with dead-letter routing,
// publisher confirms, manual ack/nack, and backoff-based retry. Nothing in
// internal/domain or internal/modules imports this package directly — they
// depend only on the events interfaces (§25).
package messaging

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Connection owns a single AMQP connection and transparently redials with
// backoff if it drops, so publishers/consumers built on top don't each
// need their own reconnect logic — they just call Channel() again.
type Connection struct {
	url    string
	logger *slog.Logger

	mu   sync.RWMutex
	conn *amqp.Connection

	done chan struct{}
}

// Connect dials RabbitMQ once (failing fast if the initial dial doesn't
// succeed — misconfigured RABBITMQ_URL should stop startup, not retry
// silently forever) and starts a background supervisor that redials with
// exponential backoff on any subsequent disconnect.
func Connect(ctx context.Context, url string, logger *slog.Logger) (*Connection, error) {
	conn, err := amqp.DialConfig(url, amqp.Config{
		Heartbeat: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("messaging: initial connect failed: %w", err)
	}

	c := &Connection{
		url:    url,
		logger: logger,
		conn:   conn,
		done:   make(chan struct{}),
	}

	go c.superviseReconnect()
	return c, nil
}

func (c *Connection) superviseReconnect() {
	for {
		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()
		if conn == nil {
			return
		}

		closeCh := conn.NotifyClose(make(chan *amqp.Error, 1))

		select {
		case <-c.done:
			return
		case amqpErr := <-closeCh:
			c.logger.Error("rabbitmq connection lost, reconnecting", slog.Any("error", amqpErr))
			c.reconnectWithBackoff()
		}
	}
}

func (c *Connection) reconnectWithBackoff() {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-c.done:
			return
		default:
		}

		conn, err := amqp.DialConfig(c.url, amqp.Config{Heartbeat: 10 * time.Second})
		if err != nil {
			c.logger.Warn("rabbitmq reconnect attempt failed", slog.Any("error", err), slog.Duration("retry_in", backoff))
			select {
			case <-c.done:
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}

		c.mu.Lock()
		c.conn = conn
		c.mu.Unlock()
		c.logger.Info("rabbitmq reconnected")
		return
	}
}

// Channel opens a new AMQP channel on the current connection. Callers
// should open one channel per publisher/consumer goroutine — channels are
// not safe for concurrent use by multiple goroutines.
func (c *Connection) Channel() (*amqp.Channel, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil || conn.IsClosed() {
		return nil, fmt.Errorf("messaging: no active rabbitmq connection")
	}
	return conn.Channel()
}

// Ping is a readiness Check function suitable for httpserver.Check.
func (c *Connection) Ping(ctx context.Context) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil || conn.IsClosed() {
		return fmt.Errorf("messaging: not connected")
	}
	return nil
}

// Close stops the reconnect supervisor and closes the underlying
// connection. Safe to call once during graceful shutdown.
func (c *Connection) Close() error {
	close(c.done)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
