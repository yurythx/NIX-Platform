package app

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/platform/messaging"
	"github.com/yurythx/nix-platform/internal/platform/ws"
)

// NewNotificationConsumer constrói o consumer que alimenta o Hub de
// WebSocket (§37/§72): RabbitMQ -> Notification Consumer -> Hub ->
// Navegador. Roda dentro do cmd/api (o Hub só existe lá), nunca no
// cmd/worker.
func NewNotificationConsumer(deps *Dependencies) *messaging.Consumer {
	return messaging.NewConsumer(
		deps.Messaging,
		messaging.QueueNotificationWebsocket.Name,
		deps.Config.RabbitMQ.PrefetchCount,
		deps.Config.RabbitMQ.MaxRetries,
		deps.Logger,
	)
}

// NotificationHandler encaminha todo evento que recebe para o Hub tal
// como está — o Hub e este handler não carregam nenhuma regra de negócio,
// só retransmitem envelopes de evento já formados para os navegadores
// conectados (§37).
func NotificationHandler(hub *ws.Hub, logger *slog.Logger) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		body, err := json.Marshal(event)
		if err != nil {
			// Deveria ser inalcançável (acabamos de desserializar este
			// mesmo envelope), mas nunca descarta uma notificação
			// silenciosamente — loga bem alto se acontecer.
			logger.Error("notification: failed to re-marshal event for broadcast", slog.Any("error", err))
			return err
		}
		hub.Broadcast(body)
		return nil
	}
}
