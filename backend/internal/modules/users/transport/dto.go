// Package transport implementa os handlers HTTP do módulo users. Não
// contém nenhuma regra de negócio — só parsing/validação de requisição,
// chamadas para application.Service, e formatação de resposta (§24).
package transport

import (
	"time"

	"github.com/yurythx/nix-platform/internal/modules/users/domain"
)

// UserResponse é o formato público de um usuário retornado pela API —
// deliberadamente não inclui KeycloakSubject, que é um detalhe interno de
// sincronização com o Keycloak, não algo que o cliente precisa ver.
type UserResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
}

func toUserResponse(u *domain.User) UserResponse {
	return UserResponse{
		ID:          u.ID.String(),
		Username:    u.Username,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Active:      u.Active,
		CreatedAt:   u.CreatedAt,
		LastSeenAt:  u.LastSeenAt,
	}
}

func toUserResponses(users []*domain.User) []UserResponse {
	out := make([]UserResponse, 0, len(users))
	for _, u := range users {
		out = append(out, toUserResponse(u))
	}
	return out
}
