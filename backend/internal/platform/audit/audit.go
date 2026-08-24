// Package audit grava a trilha de audit_logs (§49): login/logout,
// user.created/updated, integration.test, integration.config.changed,
// job.created/completed/failed. Quem chama é responsável por nunca
// colocar uma senha, access/refresh token, client secret ou segredo de
// integração em Entry.Metadata — este pacote não tenta redigir/mascarar
// conteúdo cujo formato ele não conhece; a auditoria imutável (migration
// 000008, que bloqueia UPDATE/DELETE/TRUNCATE em audit_logs) protege
// contra alteração posterior, não contra segredo indevidamente gravado.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Nomes de ação bem conhecidos (§49). Quem chama também pode usar suas
// próprias strings "<contexto>.<ação>" para eventos específicos de módulo
// não listados aqui.
const (
	ActionLogin                    = "login"
	ActionLogout                   = "logout"
	ActionUserCreated              = "user.created"
	ActionUserUpdated              = "user.updated"
	ActionIntegrationTest          = "integration.test"
	ActionIntegrationConfigChanged = "integration.config.changed"
	ActionJobCreated               = "job.created"
	ActionJobCompleted             = "job.completed"
	ActionJobFailed                = "job.failed"
	// ActionScanRequested/ActionScanCompleted/ActionScanFailed são
	// registradas pelo módulo scanning: pedido de scan (CreateScanJob),
	// scan concluído com ou sem achados (RunScan/ProcessScanJob), e scan
	// que esgotou os retries (HandleScanDeadLetter).
	ActionScanRequested = "scan.requested"
	ActionScanCompleted = "scan.completed"
	ActionScanFailed    = "scan.failed"
	// ActionProjectCreated (Fase 10) — criar um projeto por upload guarda
	// até 50MB de código-fonte de terceiros; criar por git registra uma
	// URL que passa a ser re-escaneada sem confirmação nenhuma toda vez
	// que "Rodar de novo" é clicado. As duas merecem trilha de auditoria,
	// mesmo padrão que ActionScanRequested já tem pra CreateScanJob.
	ActionProjectCreated = "project.created"
)

// Entry é um registro de auditoria.
type Entry struct {
	UserID        *uuid.UUID
	Action        string
	ResourceType  string
	ResourceID    string
	Metadata      map[string]any
	CorrelationID *uuid.UUID
	IPAddress     string
}

// execer é satisfeita tanto por *pgxpool.Pool quanto por pgx.Tx, para que
// Record possa ser usado tanto isoladamente quanto atomicamente junto de
// outras escritas numa transação já existente (ex.: gravar o audit_log de
// "user.created" na mesma transação que insere a linha do usuário).
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Writer insere linhas em audit_logs.
type Writer struct {
	db execer
}

// NewWriter constrói um Writer sobre db, que pode ser um *pgxpool.Pool
// para escritas isoladas ou um pgx.Tx para tornar a entrada de auditoria
// atômica com outras mudanças na mesma transação.
func NewWriter(db execer) *Writer {
	return &Writer{db: db}
}

// Record insere entry.
func (w *Writer) Record(ctx context.Context, entry Entry) error {
	metadata := entry.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("audit: marshal metadata: %w", err)
	}

	const q = `
		INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, metadata, correlation_id, ip_address, created_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7, NULLIF($8, '')::inet, now())
	`
	_, err = w.db.Exec(ctx, q,
		uuid.New(), entry.UserID, entry.Action, entry.ResourceType, entry.ResourceID,
		metadataJSON, entry.CorrelationID, entry.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("audit: insert entry for action %s: %w", entry.Action, err)
	}
	return nil
}
