package app

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/yurythx/nix-platform/internal/domain/events"
	"github.com/yurythx/nix-platform/internal/platform/messaging"
	"github.com/yurythx/nix-platform/internal/platform/ws"
)

// NewNotificationConsumer builds the consumer that feeds the WebSocket Hub
// (§37/§72): RabbitMQ -> Notification Consumer -> Hub -> Browser. It runs
// inside cmd/api (the Hub only exists there), not cmd/worker.
func NewNotificationConsumer(deps *Dependencies) *messaging.Consumer {
	return messaging.NewConsumer(
		deps.Messaging,
		messaging.QueueNotificationWebsocket.Name,
		deps.Config.RabbitMQ.PrefetchCount,
		deps.Config.RabbitMQ.MaxRetries,
		deps.Logger,
	)
}

// NotificationHandler forwards every event it receives to the Hub as-is —
// the Hub and this handler carry no business logic, they only relay
// already-formed event envelopes to connected browsers (§37).
func NotificationHandler(hub *ws.Hub, logger *slog.Logger) events.MessageHandler {
	return func(ctx context.Context, event events.Event) error {
		body, err := json.Marshal(event)
		if err != nil {
			// Should be unreachable (we just unmarshaled this envelope),
			// but never silently drop a notification — log loudly.
			logger.Error("notification: failed to re-marshal event for broadcast", slog.Any("error", err))
			return err
		}
		hub.Broadcast(body)
		return nil
	}
}
