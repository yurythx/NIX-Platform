package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// LocalIssuer é a identidade em nome da qual o backend assina seus
// próprios tokens (§ Sistema de Login Local) — só existe para diferenciar
// nos logs/depuração um token local de um token do Keycloak; a
// verificação em si nunca depende deste valor, só da assinatura HS256.
const LocalIssuer = "nix-platform-local"

// LocalAccount é o subconjunto de dados de um usuário local necessário
// para montar um token — deliberadamente sem PasswordHash: quem monta um
// LocalAccount já verificou a senha antes (ver internal/platform/localauth),
// este tipo nunca deveria conseguir carregar o hash por engano.
type LocalAccount struct {
	ID       string
	Username string
	Email    string
	Roles    []string
}

// localClaims é o formato do JWT que o backend assina para logins locais.
// Espelha deliberadamente o suficiente de accessTokenClaims para que
// localAccountFromClaims produza uma Identity idêntica em forma à que sai
// de um token do Keycloak — o resto da aplicação (RBAC, auditoria,
// handlers) nunca precisa saber qual dos dois caminhos autenticou o
// chamador.
type localClaims struct {
	jwt.RegisteredClaims
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Roles             []string `json:"roles"`
}

// IssueLocalToken assina um token HS256 de curta duração para account,
// usando cfg.JWTSecret. Chamado pelo handler de login local depois que a
// senha já foi conferida — este pacote nunca verifica senha, só emite e
// valida o token resultante.
func IssueLocalToken(cfg config.LocalAuthConfig, account LocalAccount) (token string, expiresAt time.Time, err error) {
	if cfg.JWTSecret == "" {
		return "", time.Time{}, fmt.Errorf("auth: local auth is not configured (LOCAL_AUTH_JWT_SECRET is empty)")
	}

	now := time.Now()
	expiresAt = now.Add(cfg.TokenTTL)
	claims := localClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    LocalIssuer,
			Subject:   account.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		PreferredUsername: account.Username,
		Email:             account.Email,
		Roles:             account.Roles,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign local token: %w", err)
	}
	return signed, expiresAt, nil
}

// verifyLocalToken confere a assinatura HS256 de rawToken contra secret e
// extrai a Identity das claims. Retorna erro para qualquer token que não
// tenha sido assinado por este mesmo processo com este mesmo segredo —
// incluindo, deliberadamente, um token de verdade do Keycloak (assinado
// com RSA, nunca validaria contra uma chave HMAC).
func verifyLocalToken(secret string, rawToken string) (Identity, error) {
	if secret == "" {
		return Identity{}, fmt.Errorf("auth: local auth is not configured")
	}

	var claims localClaims
	_, err := jwt.ParseWithClaims(rawToken, &claims, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(LocalIssuer))
	if err != nil {
		return Identity{}, fmt.Errorf("auth: local token verification failed: %w", err)
	}

	return Identity{
		Subject:  claims.Subject,
		Username: claims.PreferredUsername,
		Email:    claims.Email,
		Roles:    claims.Roles,
		Source:   SourceLocal,
	}, nil
}
