package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// discoveryTimeout limita quanto tempo NewVerifier espera pelo documento
// de discovery OIDC. Sem um teto, um issuer configurado errado (DNS que
// nunca resolve, uma rota que faz o pacote cair no buraco negro) faria o
// processo travar indefinidamente no startup, em vez de "falhar rápido"
// como o restante deste construtor promete.
const discoveryTimeout = 10 * time.Second

// Verifier valida access tokens contra o realm do Keycloak configurado
// e, opcionalmente, contra tokens locais assinados pelo próprio backend
// (§ Sistema de Login Local — sempre um caminho ADICIONAL, nunca um
// substituto do Keycloak). Faz o discovery OIDC uma única vez no startup
// e mantém o JWKS em cache no próprio processo (só é atualizado quando
// aparece um key id desconhecido, conforme a implementação de remote key
// set do go-oidc) — sem nenhuma chamada ao Keycloak por requisição (§29).
type Verifier struct {
	idTokenVerifier *oidc.IDTokenVerifier
	clientID        string
	localAuth       config.LocalAuthConfig
}

// NewVerifier faz o discovery OIDC contra cfg.IssuerURL. Falha rápido
// (retorna um erro) se o issuer estiver inalcançável ou malformado, para
// que uma configuração errada apareça no startup em vez de na primeira
// requisição que precisar validar um token. localAuth pode vir com
// Enabled=false — nesse caso Verify nunca tenta o caminho local, só
// Keycloak, exatamente como antes deste recurso existir.
func NewVerifier(ctx context.Context, cfg config.KeycloakConfig, localAuth config.LocalAuthConfig) (*Verifier, error) {
	discoveryCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(discoveryCtx, cfg.IssuerURL)
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
		localAuth:       localAuth,
	}, nil
}

// Verify valida a assinatura, o issuer, a audiência, a expiração e o
// algoritmo de rawToken, e então extrai a Identity da plataforma a partir
// das suas claims. Nunca chama o Keycloak — a verificação é inteiramente
// local, contra o JWKS em cache.
//
// Tenta primeiro o Keycloak (o caminho principal e sempre ativo); se isso
// falhar e o login local estiver habilitado, tenta a verificação HS256
// local antes de desistir. Um token de verdade do Keycloak (assinado com
// RSA) nunca passa na verificação local por acidente, e vice-versa — as
// duas verificações usam algoritmos incompatíveis, então não há ambiguidade
// possível sobre qual token "pertence" a qual caminho.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (Identity, error) {
	token, keycloakErr := v.idTokenVerifier.Verify(ctx, rawToken)
	if keycloakErr == nil {
		var claims accessTokenClaims
		if err := token.Claims(&claims); err != nil {
			return Identity{}, fmt.Errorf("auth: decode token claims: %w", err)
		}
		return claims.toIdentity(v.clientID), nil
	}

	if !v.localAuth.Enabled {
		return Identity{}, fmt.Errorf("auth: token verification failed: %w", keycloakErr)
	}

	identity, localErr := verifyLocalToken(v.localAuth.JWTSecret, rawToken)
	if localErr != nil {
		// Nenhum dos dois caminhos aceitou o token — reporta o erro do
		// Keycloak, já que é o caminho principal e o mais provável de ser
		// o que o chamador esperava usar.
		return Identity{}, fmt.Errorf("auth: token verification failed: %w", keycloakErr)
	}
	return identity, nil
}
