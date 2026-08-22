// Package transport implementa os handlers HTTP do módulo integrations.
package transport

import (
	"time"

	"github.com/yurythx/nix-platform/internal/modules/integrations/domain"
)

// IntegrationResponse é o formato público de uma integração (§74).
type IntegrationResponse struct {
	ID            string     `json:"id"`
	Key           string     `json:"key"`
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	Enabled       bool       `json:"enabled"`
	Status        string     `json:"status"`
	LastCheckAt   *time.Time `json:"last_check_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"`
}

func toIntegrationResponse(i *domain.Integration) IntegrationResponse {
	return IntegrationResponse{
		ID:            i.ID.String(),
		Key:           i.Key,
		Name:          i.Name,
		Type:          i.Type,
		Enabled:       i.Enabled,
		Status:        string(i.Status),
		LastCheckAt:   i.LastCheckAt,
		LastSuccessAt: i.LastSuccessAt,
		LastError:     i.LastError,
	}
}

func toIntegrationResponses(list []*domain.Integration) []IntegrationResponse {
	out := make([]IntegrationResponse, 0, len(list))
	for _, i := range list {
		out = append(out, toIntegrationResponse(i))
	}
	return out
}
