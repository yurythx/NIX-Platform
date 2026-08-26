package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	vars := map[string]string{
		"APP_ENV":             "development",
		"DB_HOST":             "localhost",
		"DB_PORT":             "5432",
		"DB_NAME":             "nix",
		"DB_USER":             "nix",
		"DB_PASSWORD":         "secret",
		"RABBITMQ_URL":        "amqp://guest:guest@localhost:5672/",
		"KEYCLOAK_ISSUER_URL": "https://idp.example.com/realms/nix",
		"KEYCLOAK_REALM":      "nix",
		"KEYCLOAK_CLIENT_ID":  "nix-platform",
		"KEYCLOAK_AUDIENCE":   "nix-platform",
	}
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func TestLoad_Success(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Database.Host != "localhost" {
		t.Errorf("expected DB host localhost, got %q", cfg.Database.Host)
	}
	if cfg.HTTP.Port != 8000 {
		t.Errorf("expected default HTTP port 8000, got %d", cfg.HTTP.Port)
	}
	if cfg.RabbitMQ.MaxRetries != 3 {
		t.Errorf("expected default max retries 3, got %d", cfg.RabbitMQ.MaxRetries)
	}
	if cfg.Jobs.StaleAfter != 45*time.Minute {
		t.Errorf("expected default job stale-after 45m, got %v", cfg.Jobs.StaleAfter)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	// Deixa DB_HOST, RABBITMQ_URL, KEYCLOAK_* sem definir, de propósito.

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing required env vars, got nil")
	}
}

func TestLoad_InvalidAppEnv(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("APP_ENV", "not-a-real-env")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid APP_ENV, got nil")
	}
}

func TestLoad_SecretFromFile_TakesPrecedenceOverDirectEnvVar(t *testing.T) {
	setRequiredEnv(t)

	secretFile := filepath.Join(t.TempDir(), "db_password")
	if err := os.WriteFile(secretFile, []byte("password-from-file\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	t.Setenv("DB_PASSWORD_FILE", secretFile)
	// Continua definida (por setRequiredEnv) como "secret" — o valor do
	// arquivo deve vencer, simulando Docker/Kubernetes secrets montados
	// como arquivo tendo prioridade sobre uma env var direta.
	t.Setenv("DB_PASSWORD", "should-be-ignored")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if cfg.Database.Password != "password-from-file" {
		t.Errorf("Database.Password = %q, want %q (do arquivo, com espaços/quebra de linha removidos)", cfg.Database.Password, "password-from-file")
	}
}

func TestLoad_SecretFile_MissingFileIsAConfigError(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DB_PASSWORD_FILE", "/does/not/exist")

	_, err := Load()
	if err == nil {
		t.Fatal("esperava um erro quando DB_PASSWORD_FILE aponta para um arquivo inexistente")
	}
}

func TestDatabaseConfig_DSN(t *testing.T) {
	db := DatabaseConfig{
		Host: "db", Port: 5432, Name: "nix", User: "nix", Password: "pw",
		SSLMode: "disable", ConnectTimeout: 5 * time.Second,
	}
	dsn := db.DSN()
	want := "host=db port=5432 dbname=nix user=nix password=pw sslmode=disable connect_timeout=5"
	if dsn != want {
		t.Errorf("DSN() = %q, want %q", dsn, want)
	}
}

// TestLoadDatabase_Success confirma que LoadDatabase lê só as variáveis
// DB_* — sem precisar de nenhuma das outras exigidas por Load()
// (RABBITMQ_URL, KEYCLOAK_*), o motivo dela existir (cmd/seedadmin não
// deveria precisar de um Keycloak/RabbitMQ configurados só pra escrever
// uma linha em "users").
func TestLoadDatabase_Success(t *testing.T) {
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_NAME", "nix")
	t.Setenv("DB_USER", "nix")
	t.Setenv("DB_PASSWORD", "secret")

	db, err := LoadDatabase()
	if err != nil {
		t.Fatalf("LoadDatabase: %v", err)
	}
	if db.Host != "localhost" || db.Port != 5432 || db.Name != "nix" || db.User != "nix" || db.Password != "secret" {
		t.Errorf("LoadDatabase() = %+v, want host/port/name/user/password from env", db)
	}
	if db.SSLMode != "disable" {
		t.Errorf("SSLMode default = %q, want disable", db.SSLMode)
	}
}

func TestLoadDatabase_MissingRequired(t *testing.T) {
	// Nenhuma variável DB_* definida de propósito.
	_, err := LoadDatabase()
	if err == nil {
		t.Fatal("expected error for missing required DB_* env vars, got nil")
	}
}

func TestSplitAndTrim(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"staging.example.com", []string{"staging.example.com"}},
		{"a.example.com, b.example.com,c.example.com", []string{"a.example.com", "b.example.com", "c.example.com"}},
		{" , a.example.com , ,", []string{"a.example.com"}}, // vírgulas sobrando e espaço não viram entradas fantasma
	}
	for _, tc := range cases {
		got := splitAndTrim(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitAndTrim(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitAndTrim(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}
