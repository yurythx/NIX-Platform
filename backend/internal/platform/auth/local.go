package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yurythx/nix-platform/internal/platform/config"
)

// LocalIssuer é a identidade em nome da qual o backend assina seus
// próprios tokens locais (§ Sistema de Login Local), usada tanto como
// "iss" quanto como "aud" das claims — os dois únicos participantes deste
// protocolo são "este mesmo processo assina" e "este mesmo processo
// verifica", então issuer e audience coincidem deliberadamente. Também
// serve para diferenciar nos logs/depuração um token local de um token do
// Keycloak.
const LocalIssuer = "nix-platform-local"

// minRSAKeyBits é o tamanho mínimo de chave aceito por NewLocalSigner —
// abaixo disso a assinatura RSA não é mais considerada segura pelos
// padrões atuais (NIST SP 800-57 recomenda 2048 bits como piso).
const minRSAKeyBits = 2048

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
// LocalSigner.verifyToken produza uma Identity idêntica em forma à que sai
// de um token do Keycloak — o resto da aplicação (RBAC, auditoria,
// handlers) nunca precisa saber qual dos dois caminhos autenticou o
// chamador.
type localClaims struct {
	jwt.RegisteredClaims
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Roles             []string `json:"roles"`
}

// LocalSigner assina e verifica os tokens do login local com um par de
// chaves RSA (RS256) PRÓPRIO — nunca compartilhado com o Keycloak/SSO, nem
// com nenhum outro segredo da aplicação (§ Sistema de Login Local: "um
// login separado do SSO"). Construído uma única vez no bootstrap
// (internal/app/dependencies.go) a partir de config.LocalAuthConfig; um
// *LocalSigner nil em qualquer ponto downstream (Verifier, localauth.Handlers)
// significa "login local desligado" — a checagem de nil substitui um campo
// booleano "Enabled" espalhado por múltiplas camadas.
type LocalSigner struct {
	privateKey *rsa.PrivateKey
	tokenTTL   time.Duration
}

// NewLocalSigner analisa cfg.PrivateKeyPEM e monta um LocalSigner pronto
// para assinar/verificar. Retorna (nil, nil) — não um erro — quando
// cfg.Enabled é false, já que não há nada para configurar nesse caso; a
// validação de que PrivateKeyPEM está presente quando Enabled=true já
// aconteceu em config.Load (fail fast na configuração, antes de chegar
// aqui). Falha (erro, não nil) para qualquer PEM inválido ou chave menor
// que minRSAKeyBits — a aplicação deve recusar subir com uma chave fraca
// em vez de aceitar silenciosamente.
func NewLocalSigner(cfg config.LocalAuthConfig) (*LocalSigner, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	key, err := parseRSAPrivateKeyPEM(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("auth: parse LOCAL_AUTH_PRIVATE_KEY: %w", err)
	}
	if bits := key.N.BitLen(); bits < minRSAKeyBits {
		return nil, fmt.Errorf("auth: LOCAL_AUTH_PRIVATE_KEY is %d bits, minimum is %d", bits, minRSAKeyBits)
	}

	// Sem normalização de TokenTTL aqui: config.Load já garante um
	// default de 1h quando LOCAL_AUTH_TOKEN_TTL não é definida
	// (l.durationVal), e um valor negativo/zero passado deliberadamente
	// (como um teste construindo um token já expirado) deve ser
	// respeitado, não silenciosamente substituído.
	return &LocalSigner{privateKey: key, tokenTTL: cfg.TokenTTL}, nil
}

// parseRSAPrivateKeyPEM aceita tanto PKCS1 ("BEGIN RSA PRIVATE KEY") quanto
// PKCS8 ("BEGIN PRIVATE KEY") — os dois formatos que `openssl genrsa`/`openssl
// genpkey` produzem, dependendo da versão/flags usadas, para não forçar
// quem está gerando a chave a acertar o formato exato.
func parseRSAPrivateKeyPEM(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a valid PKCS1 or PKCS8 RSA private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM key is not an RSA private key (got %T)", keyAny)
	}
	return key, nil
}

// IssueToken assina um token RS256 de curta duração para account. Chamado
// pelo handler de login local depois que a senha já foi conferida — este
// tipo nunca verifica senha, só emite e valida o token resultante.
func (s *LocalSigner) IssueToken(account LocalAccount) (token string, expiresAt time.Time, err error) {
	now := time.Now()
	expiresAt = now.Add(s.tokenTTL)
	claims := localClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    LocalIssuer,
			Audience:  jwt.ClaimStrings{LocalIssuer},
			Subject:   account.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		PreferredUsername: account.Username,
		Email:             account.Email,
		Roles:             account.Roles,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign local token: %w", err)
	}
	return signed, expiresAt, nil
}

// verifyToken confere a assinatura RS256 de rawToken contra a chave
// pública derivada de s.privateKey, e a issuer/audience/expiração das
// claims, extraindo a Identity resultante. Retorna erro para qualquer
// token que não tenha sido assinado por este mesmo processo com esta
// mesma chave — incluindo, deliberadamente, um token de verdade do
// Keycloak (assinado por uma chave RSA completamente diferente, a do
// realm, nunca a local).
func (s *LocalSigner) verifyToken(rawToken string) (Identity, error) {
	var claims localClaims
	_, err := jwt.ParseWithClaims(rawToken, &claims, func(t *jwt.Token) (any, error) {
		return &s.privateKey.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(LocalIssuer),
		jwt.WithAudience(LocalIssuer),
	)
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
