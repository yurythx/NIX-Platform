// Package auth valida os access tokens OIDC emitidos pelo Keycloak externo
// já existente (discovery + JWKS em cache, nunca uma chamada por
// requisição ao Keycloak — §29) e fornece middlewares chi para
// autenticação e autorização baseada em roles/permissões (§31).
package auth

import "context"

// Source identifica qual verificador aceitou o token que produziu uma
// Identity — o §32/GetCurrentUser precisa disso para saber COMO buscar o
// usuário: um Subject do Keycloak é o "sub" externo (chave de
// upsert-por-keycloak_subject), enquanto um Subject local já É o id
// interno da linha em "users" (a conta local não precisa — nem pode —
// passar por upsert, ela já existe por definição).
type Source string

const (
	SourceKeycloak Source = "keycloak"
	SourceLocal    Source = "local"
)

// Identity é o chamador autenticado, extraído de um access token já
// verificado. Nunca carrega o token bruto em si — só o que os handlers
// precisam (quem é o usuário e quais roles ele tem).
type Identity struct {
	Subject  string   // claim "sub" — id externo do Keycloak OU id interno de users, dependendo de Source
	Username string   // "preferred_username"
	Email    string   // "email"
	Roles    []string // roles de realm + de client (Keycloak), ou a coluna users.roles (local)
	Source   Source   // qual verificador emitiu esta identidade — ver o comentário de Source
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
