package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yurythx/nix-platform/internal/domain/pagination"
)

// Repository abstrai a persistência do monitoramento do Diário Oficial —
// interface PRÓPRIA (não um método a mais em algum Repository genérico
// da plataforma), mesmo raciocínio de scanning.domain.TriageRepository:
// este módulo é o único que precisa destes métodos.
type Repository interface {
	// CreateMonitoredTerm grava um termo novo. Não precisa de tx/outbox —
	// cadastrar o QUE monitorar não é um evento de negócio que o resto
	// da plataforma precisa saber (ao contrário de um match, ver
	// CreateMatch).
	CreateMonitoredTerm(ctx context.Context, term MonitoredTerm) error

	// ListMonitoredTerms lista todo termo cadastrado, mais recente
	// primeiro. onlyActive=true filtra pra Active=true — o que o worker
	// usa pra decidir o que sincronizar a cada ciclo (um termo pausado
	// não deveria gastar chamada nenhuma contra o provedor externo).
	ListMonitoredTerms(ctx context.Context, onlyActive bool) ([]MonitoredTerm, error)

	// GetMonitoredTerm busca um termo por id — apperrors.NotFound (na
	// camada application) se não existir.
	GetMonitoredTerm(ctx context.Context, id uuid.UUID) (*MonitoredTerm, error)

	// DeleteMonitoredTerm remove um termo. As publicações/matches já
	// gravados são removidos em cascata (ver migration 000026's
	// ON DELETE CASCADE) — o histórico de UM termo apagado não faz
	// sentido continuar aparecendo num feed de "achados recentes", ao
	// contrário do módulo scanning (onde achado histórico sobrevive à
	// exclusão por design).
	DeleteMonitoredTerm(ctx context.Context, id uuid.UUID) error

	// UpdateLastSyncedAt marca até onde este termo já foi sincronizado —
	// gravado NA MESMA transação do upsert de publicações/matches deste
	// ciclo (ver application.syncTerm), para que "o termo foi
	// sincronizado até T" e "as publicações encontradas até T foram
	// persistidas" nunca fiquem inconsistentes entre si.
	UpdateLastSyncedAt(ctx context.Context, tx pgx.Tx, id uuid.UUID, at time.Time) error

	// UpsertPublication grava pub se external_id ainda não existe
	// (ON CONFLICT (external_id) DO NOTHING) — isNew reporta se esta
	// chamada de fato inseriu a linha (false = já existia de um ciclo
	// anterior, storedID é o id JÁ EXISTENTE, não um novo). Dentro da tx
	// de quem chama, junto com CreateMatch — ver syncTerm.
	UpsertPublication(ctx context.Context, tx pgx.Tx, pub Publication) (storedID uuid.UUID, isNew bool, err error)

	// CreateMatch grava que publicationID casou com monitoredTermID —
	// ON CONFLICT (publication_id, monitored_term_id) DO NOTHING, isNew
	// reporta se este casamento é NOVO (nunca visto antes): só um match
	// novo justifica publicar diario_oficial.publication.matched — a
	// mesma publicação re-encontrada num ciclo seguinte (janela de busca
	// sobreposta de propósito) não deveria notificar de novo.
	CreateMatch(ctx context.Context, tx pgx.Tx, publicationID, monitoredTermID uuid.UUID) (isNew bool, err error)

	// ListPublicationsForTerm lista as publicações que casaram com
	// termID, mais recentes primeiro (por MatchedAt).
	ListPublicationsForTerm(ctx context.Context, termID uuid.UUID, params pagination.Params) ([]MatchedPublication, int64, error)

	// ListRecentMatches lista os casamentos mais recentes entre TODO
	// termo ativo ou não — o feed agregado, mesmo raciocínio de
	// scanning.Repository.ListRecentPage: quem consome não precisa já
	// saber um termo específico de antemão.
	ListRecentMatches(ctx context.Context, params pagination.Params) ([]MatchedPublication, int64, error)
}
