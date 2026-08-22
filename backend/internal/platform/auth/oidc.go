package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// Verifier validates OIDC access tokens against the configured Keycloak
// realm. It performs OIDC discovery once at startup and caches the JWKS
// in-process (refreshed only on an unrecognized key id, per go-oidc's
// remote key set implementation) — no per-request call to Keycloak.
type Verifier struct {
	idTokenVerifier *oidc.IDTokenVerifier
	clientID        string
}

// NewVerifier performs OIDC discovery against cfg.IssuerURL. It fails fast
// (returns an error) if the issuer is unreachable or malformed, so
// misconfiguration surfaces at startup instead of on the first request.
func NewVerifier(ctx context.Context, cfg config.KeycloakConfig) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC discovery failed for issuer %q: %w", cfg.IssuerURL, err)
	}

	verifier := provider.VerifierContext(ctx, &oidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256},
	})

	return &Verifier{
		idTokenVerifier: verifier,
		clientID:        cfg.ClientID,
	}, nil
}

// Verify validates rawToken's signature, issuer, audience, expiry and
// algorithm, then extracts the platform Identity from its claims. It never
// calls out to Keycloak — verification is entirely local against the
// cached JWKS.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (Identity, error) {
	token, err := v.idTokenVerifier.Verify(ctx, rawToken)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: token verification failed: %w", err)
	}

	var claims accessTokenClaims
	if err := token.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("auth: decode token claims: %w", err)
	}

	return claims.toIdentity(v.clientID), nil
}
