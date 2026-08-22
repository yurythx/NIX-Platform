// Package auth valida os access tokens OIDC emitidos pelo Keycloak externo
// já existente (discovery + JWKS em cache, nunca uma chamada por
// requisição ao Keycloak — §29) e fornece middlewares chi para
// autenticação e autorização baseada em roles/permissões (§31).
package auth

import "context"

// Identity é o chamador autenticado, extraído de um access token já
// verificado. Nunca carrega o token bruto em si — só o que os handlers
// precisam (quem é o usuário e quais roles ele tem).
type Identity struct {
	Subject  string   // claim "sub" do Keycloak — o id externo estável do usuário
	Username string   // "preferred_username"
	Email    string   // "email"
	Roles    []string // roles de realm + de client, mesclados e sem duplicatas
}

// HasRole reporta se a identidade recebeu o role informado.
func (i Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole reporta se a identidade tem pelo menos um dos roles
// informados.
func (i Identity) HasAnyRole(roles ...string) bool {
	for _, want := range roles {
		if i.HasRole(want) {
			return true
		}
	}
	return false
}

type ctxKey string

const identityCtxKey ctxKey = "auth.identity"

// WithIdentity retorna um context carregando a identidade autenticada.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey, id)
}

// IdentityFromContext extrai a identidade gravada por RequireAuthentication.
// ok é false se a requisição nunca foi autenticada.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityCtxKey).(Identity)
	return id, ok
}
