// Package messaging implementa o adaptador RabbitMQ para as abstrações
// events.EventPublisher/EventConsumer da plataforma: um exchange topic
// (nix.events), filas duráveis por módulo com roteamento de dead-letter,
// publisher confirms, ack/nack manual e retry baseado em backoff. Nada em
// internal/domain nem em internal/modules importa este pacote diretamente
// — eles dependem apenas das interfaces de events (§25), então trocar
// RabbitMQ por outro broker no futuro não tocaria a camada de domínio.
package messaging

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Connection possui uma única conexão AMQP e a redisca automaticamente com
// backoff caso ela caia, para que publishers/consumers construídos por
// cima não precisem cada um da sua própria lógica de reconexão — eles só
// chamam Channel() de novo.
type Connection struct {
	url    string
	logger *slog.Logger

	mu   sync.RWMutex
	conn *amqp.Connection

	done chan struct{}
}

// Connect disca o RabbitMQ uma vez (falhando rápido se a discagem inicial
// não funcionar — uma RABBITMQ_URL mal configurada deve parar o startup,
// não ficar tentando de novo silenciosamente para sempre) e inicia um
// supervisor em background que redisca com backoff exponencial em
// qualquer desconexão subsequente.
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

// superviseReconnect fica escutando o canal de fechamento da conexão AMQP
// atual; quando ela cai (crash do broker, rede instável, etc.), aciona
// reconnectWithBackoff e volta a escutar a nova conexão assim que ela for
// restabelecida. Roda para sempre até Close() fechar o canal done.
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

// reconnectWithBackoff tenta redisial repetidamente, dobrando o intervalo
// de espera a cada falha (1s, 2s, 4s, ... até um teto de 30s) em vez de
// martelar o broker com tentativas imediatas enquanto ele está
// reiniciando ou a rede está instável.
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

// Channel abre um novo canal AMQP na conexão atual. Quem chama deve abrir
// um canal por goroutine de publisher/consumer — canais não são seguros
// para uso concorrente por múltiplas goroutines ao mesmo tempo.
func (c *Connection) Channel() (*amqp.Channel, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil || conn.IsClosed() {
		return nil, fmt.Errorf("messaging: no active rabbitmq connection")
	}
	return conn.Channel()
}

// Ping é uma função de verificação (Check) de readiness, compatível com
// httpserver.Check — usada pelo endpoint /ready para reportar se o
// RabbitMQ está conectado.
func (c *Connection) Ping(ctx context.Context) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil || conn.IsClosed() {
		return fmt.Errorf("messaging: not connected")
	}
	return nil
}

// Close para o supervisor de reconexão e fecha a conexão subjacente.
// Seguro de chamar uma vez durante o graceful shutdown.
func (c *Connection) Close() error {
	close(c.done)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
