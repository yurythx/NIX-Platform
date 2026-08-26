// Command seedadmin cria (ou reseta a senha de) uma conta local de
// administrador com uma senha ALEATÓRIA, gerada nesta execução e nunca
// gravada em lugar nenhum além da tela — impressa uma única vez para o
// operador copiar.
//
// Achado de auditoria de segurança (revisão pedida pelo usuário — "aplique
// todas as melhores práticas"): antes deste comando, o único jeito de ter
// um usuário local pronto pra uso era a migration 000011, que semeava
// admin/Admin123! — uma senha conhecida PUBLICAMENTE (documentada no
// README), removida pela migration 000027 justamente porque um aviso de
// "troque antes de produção" é disciplina humana, não um controle
// técnico. Este comando é a forma correta de repor esse acesso: uma senha
// que só existe na memória de quem rodou o comando, nunca versionada.
//
// Standalone de propósito (não passa por internal/app.NewDependencies,
// que exigiria Keycloak/RabbitMQ configurados só pra escrever uma linha
// em "users") — mesmo raciocínio de cmd/secscan: só o que este comando de
// fato precisa (config.LoadDatabase, não config.Load).
//
//	make seed-admin
//	# ou, direto:
//	DB_HOST=localhost DB_PORT=5432 DB_NAME=nix DB_USER=nix DB_PASSWORD=... \
//	  go run ./cmd/seedadmin --username admin --roles nix-admin,nix-user
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/yurythx/nix-platform/internal/platform/config"
	"github.com/yurythx/nix-platform/internal/platform/database"
)

// passwordBytes: 18 bytes aleatórios (144 bits de entropia) codificados em
// base64 URL-safe — bem acima do que qualquer política de composição de
// senha exigiria, e uma senha gerada por máquina não precisa de regras de
// composição (maiúscula/dígito/símbolo) pra ser forte: comprimento +
// entropia de verdade importam mais que forma, e regras de composição só
// fariam sentido pra guiar um HUMANO escolhendo a própria senha (NIST SP
// 800-63B já recomenda contra exigir isso de senhas geradas por máquina).
const passwordBytes = 18

func main() {
	username := flag.String("username", "admin", "username da conta local a criar/resetar")
	email := flag.String("email", "admin@nix.local", "email da conta")
	displayName := flag.String("display-name", "Administrador (local)", "nome de exibição")
	rolesCSV := flag.String("roles", "nix-admin,nix-user", "roles, separadas por vírgula")
	// password: SÓ para automação (CI de E2E, ver .github/workflows/ci.yml)
	// que precisa saber a senha de antemão pra digitar num formulário —
	// deixado vazio (o padrão), uma senha aleatória de verdade é gerada.
	// Nunca documentado como o jeito recomendado de uso interativo.
	password := flag.String("password", "", "senha a usar em vez de gerar uma aleatória (só para automação — ex.: CI de E2E)")
	flag.Parse()

	if err := run(*username, *email, *displayName, *rolesCSV, *password); err != nil {
		fmt.Fprintln(os.Stderr, "seedadmin:", err)
		os.Exit(1)
	}
}

func run(username, email, displayName, rolesCSV, passwordOverride string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbCfg, err := config.LoadDatabase()
	if err != nil {
		return fmt.Errorf("load database config (DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD): %w", err)
	}
	pool, err := database.New(ctx, dbCfg)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	password, err := seedAdmin(ctx, pool, username, email, displayName, rolesCSV, passwordOverride)
	if err != nil {
		return err
	}

	fmt.Println("============================================================")
	fmt.Printf("Usuário local pronto: %s\n", username)
	fmt.Printf("Senha: %s\n", password)
	fmt.Println("Esta senha só aparece aqui — não fica salva em nenhum arquivo,")
	fmt.Println("log ou variável de ambiente. Guarde-a agora.")
	fmt.Println("============================================================")
	return nil
}

// seedAdmin faz o trabalho de verdade (checagem de conflito com Keycloak,
// geração de senha, upsert) contra um pool já conectado — separado de
// run() pra ser testável com um Postgres real (ver seed_test.go) sem
// precisar passar por config.LoadDatabase/variáveis de ambiente.
// passwordOverride vazio (o caso normal) gera uma senha aleatória; não
// vazio (só automação, ver a flag --password) usa exatamente esse valor.
func seedAdmin(ctx context.Context, pool *pgxpool.Pool, username, email, displayName, rolesCSV, passwordOverride string) (string, error) {
	// Nunca sobrescreve silenciosamente uma conta ligada ao Keycloak —
	// mesmo que o username coincida, uma conta SSO nunca deveria virar
	// uma conta de senha local por acidente de execução deste comando.
	var existingKeycloakSubject *string
	err := pool.QueryRow(ctx, `SELECT keycloak_subject FROM users WHERE username = $1`, username).Scan(&existingKeycloakSubject)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("check existing user: %w", err)
	}
	if existingKeycloakSubject != nil {
		return "", fmt.Errorf("user %q already exists and is linked to Keycloak (subject %q) — refusing to convert it to a local-password account", username, *existingKeycloakSubject)
	}

	password := passwordOverride
	if password == "" {
		var err error
		password, err = generatePassword()
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	roles := splitRoles(rolesCSV)

	// ON CONFLICT (username): idx_users_username (migration 000002) é
	// UNIQUE — rodar este comando de novo contra um username já existente
	// (sem keycloak_subject, checado acima) RESETA a senha e o bloqueio de
	// conta em vez de falhar, o caso de uso mais comum de rodar isto uma
	// segunda vez (esqueceu a senha gerada da primeira vez).
	const q = `
		INSERT INTO users (id, keycloak_subject, username, email, display_name, active, password_hash, roles, created_at, updated_at)
		VALUES ($1, NULL, $2, $3, $4, true, $5, $6, now(), now())
		ON CONFLICT (username) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			roles = EXCLUDED.roles,
			display_name = EXCLUDED.display_name,
			active = true,
			failed_login_attempts = 0,
			locked_until = NULL,
			updated_at = now()
	`
	if _, err := pool.Exec(ctx, q, uuid.New(), username, email, displayName, string(hash), roles); err != nil {
		return "", fmt.Errorf("upsert local admin user: %w", err)
	}

	return password, nil
}

func generatePassword() (string, error) {
	raw := make([]byte, passwordBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func splitRoles(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
