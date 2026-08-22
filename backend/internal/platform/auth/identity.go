// Package auth validates OIDC access tokens issued by the existing
// external Keycloak (discovery + cached JWKS, never a per-request call to
// Keycloak — §29) and provides chi middleware for authentication and
// role/permission-based authorization (§31).
package auth

import "context"

// Identity is the authenticated caller extracted from a verified access
// token. It never carries the raw token itself — only what handlers need.
type Identity struct {
	Subject  string   // Keycloak "sub" claim — the stable external user id
	Username string   // "preferred_username"
	Email    string   // "email"
	Roles    []string // realm + client roles, merged and de-duplicated
}

// HasRole reports whether the identity has been granted role.
func (i Identity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole reports whether the identity has at least one of roles.
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

// WithIdentity returns a context carrying the authenticated identity.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey, id)
}

// IdentityFromContext extracts the identity stored by RequireAuthentication.
// ok is false if the request was never authenticated.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityCtxKey).(Identity)
	return id, ok
}
