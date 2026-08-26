// Arquivo monitoring.go — o MVP real de monitoramento do Diário Oficial
// (docs/roadmap-secops-orchestrator.md, "Diário Oficial — monitoramento
// real via DJEN"): até aqui, este módulo só fazia um teste de
// conectividade (service.go). CreateMonitoredTerm/ListMonitoredTerms/
// DeleteMonitoredTerm são o CRUD do que o usuário quer acompanhar;
// SyncAll é o que o worker roda periodicamente (ver
// worker.DiarioOficialSyncLoop) pra de fato buscar no DJEN e notificar
// quando uma publicação nova casa com um termo.
package application

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/diario_oficial/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/database"
)

const (
	EventPublicationMatched = "diario_oficial.publication.matched"

	// defaultLookbackWindow: a janela de busca na PRIMEIRA sincronização
	// de um termo novo (LastSyncedAt == nil) — mostra contexto histórico
	// recente assim que alguém cadastra um termo, em vez de só notificar
	// publicações a partir de agora (o mesmo comportamento que produtos
	// de monitoramento jurídico de mercado já oferecem: cadastrar um OAB
	// mostra o que já saiu recentemente, não só o que sair dali pra
	// frente).
	defaultLookbackWindow = 30 * 24 * time.Hour

	// syncOverlapWindow: todo ciclo de sync depois do primeiro busca a
	// partir de LastSyncedAt MENOS esta margem, nunca exatamente de
	// LastSyncedAt — o DJEN filtra por data (não data+hora) de
	// disponibilização, então uma publicação do fim do dia anterior
	// poderia ficar de fora por uma margem de horas se a janela não
	// sobrepusesse um pouco. UpsertPublication (ON CONFLICT DO NOTHING)
	// e CreateMatch (idem) tornam essa sobreposição segura de reprocessar
	// sem duplicar publicação nem notificação.
	syncOverlapWindow = 24 * time.Hour

	// maxSyncPagesPerTerm: teto de páginas buscadas no DJEN por termo por
	// ciclo — um limite de segurança pra nunca um único termo com volume
	// alto de publicação (ex.: um escritório com centenas de processos
	// sob o mesmo texto livre) segurar o worker indefinidamente. Um termo
	// que bate o teto é sincronizado até aqui neste ciclo; o restante
	// aparece no próximo (LastSyncedAt só avança até onde de fato
	// buscamos).
	maxSyncPagesPerTerm = 5
)

// CreateMonitoredTerm cadastra um termo novo — validado por
// domain.MonitoredTerm.Validate antes de qualquer ida ao banco.
func (s *Service) CreateMonitoredTerm(ctx context.Context, term domain.MonitoredTerm, requestedBy *uuid.UUID) (*domain.MonitoredTerm, error) {
	term.ID = uuid.New()
	term.Active = true
	term.CreatedBy = requestedBy
	now := time.Now()
	term.CreatedAt = now
	term.UpdatedAt = now

	if err := term.Validate(); err != nil {
		return nil, apperrors.Validation(err.Error())
	}

	if err := s.repo.CreateMonitoredTerm(ctx, term); err != nil {
		return nil, fmt.Errorf("diario_oficial: create monitored term: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:       requestedBy,
			Action:       audit.ActionMonitoredTermCreated,
			ResourceType: "diario_oficial_monitored_term",
			ResourceID:   term.ID.String(),
			Metadata:     map[string]any{"label": term.Label},
		})
	}

	return &term, nil
}

// ListMonitoredTerms lista todo termo cadastrado, mais recente primeiro.
func (s *Service) ListMonitoredTerms(ctx context.Context) ([]domain.MonitoredTerm, error) {
	terms, err := s.repo.ListMonitoredTerms(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("diario_oficial: list monitored terms: %w", err)
	}
	return terms, nil
}

// DeleteMonitoredTerm remove um termo — publicações/matches já
// encontrados somem em cascata (ver migration 000026).
func (s *Service) DeleteMonitoredTerm(ctx context.Context, id uuid.UUID, requestedBy *uuid.UUID) error {
	if err := s.repo.DeleteMonitoredTerm(ctx, id); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:       requestedBy,
			Action:       audit.ActionMonitoredTermDeleted,
			ResourceType: "diario_oficial_monitored_term",
			ResourceID:   id.String(),
		})
	}
	return nil
}

// ListPublicationsForTerm lista as publicações que casaram com termID,
// mais recentes primeiro.
func (s *Service) ListPublicationsForTerm(ctx context.Context, termID uuid.UUID, page, pageSize int) ([]domain.MatchedPublication, pagination.Meta, error) {
	params := pagination.New(page, pageSize, pagination.AbsoluteMaxPageSize)
	items, total, err := s.repo.ListPublicationsForTerm(ctx, termID, params)
	if err != nil {
		return nil, pagination.Meta{}, fmt.Errorf("diario_oficial: list publications for term: %w", err)
	}
	return items, pagination.NewMeta(params, total), nil
}

// ListRecentMatches lista os casamentos mais recentes entre todo termo —
// o feed agregado (equivalente diario_oficial de
// scanning.ListRecentScans).
func (s *Service) ListRecentMatches(ctx context.Context, page, pageSize int) ([]domain.MatchedPublication, pagination.Meta, error) {
	params := pagination.New(page, pageSize, pagination.AbsoluteMaxPageSize)
	items, total, err := s.repo.ListRecentMatches(ctx, params)
	if err != nil {
		return nil, pagination.Meta{}, fmt.Errorf("diario_oficial: list recent matches: %w", err)
	}
	return items, pagination.NewMeta(params, total), nil
}

// SyncAll sincroniza todo termo ATIVO contra o DJEN — chamado
// periodicamente por worker.DiarioOficialSyncLoop (nunca via HTTP: não
// existe um "sincronizar agora" sob demanda nesta primeira versão, ver
// docs/roadmap-secops-orchestrator.md). Respeita a MESMA feature flag que
// CreateTestJob já usa (diario_oficial_scraping_enabled) — o mesmo
// interruptor de emergência cobre tanto o teste de conectividade quanto
// a sincronização de verdade, já que as duas batem no mesmo provedor
// externo.
//
// Uma falha isolada num termo (o DJEN retorna erro só pra aquela busca
// específica, por exemplo) não interrompe os demais — best-effort por
// termo, logado, nunca propagado pro chamador: o próximo ciclo tenta de
// novo sozinho (mesmo raciocínio de scanning.worker.snapshotOnce).
func (s *Service) SyncAll(ctx context.Context) {
	if s.flags != nil {
		enabled, err := s.flags.IsEnabled(ctx, FeatureFlagKey, true)
		if err != nil {
			s.logger.Error("diario_oficial: check feature flag before sync, skipping this cycle", slog.Any("error", err))
			return
		}
		if !enabled {
			s.logger.Info("diario_oficial: sync skipped, feature disabled", slog.String("flag", FeatureFlagKey))
			return
		}
	}

	terms, err := s.repo.ListMonitoredTerms(ctx, true)
	if err != nil {
		s.logger.Error("diario_oficial: list active monitored terms for sync, skipping this cycle", slog.Any("error", err))
		return
	}

	for _, term := range terms {
		newMatches, err := s.syncTerm(ctx, term)
		if err != nil {
			s.logger.Error("diario_oficial: sync term failed, will retry next cycle",
				slog.String("term_id", term.ID.String()), slog.String("label", term.Label), slog.Any("error", err))
			continue
		}
		if newMatches > 0 {
			s.logger.Info("diario_oficial: sync term found new matches",
				slog.String("term_id", term.ID.String()), slog.String("label", term.Label), slog.Int("new_matches", newMatches))
		}
	}
}

// syncSinceDate decide o ponto de partida da busca pra term — ver
// defaultLookbackWindow/syncOverlapWindow.
func syncSinceDate(term domain.MonitoredTerm, now time.Time) time.Time {
	if term.LastSyncedAt == nil {
		return now.Add(-defaultLookbackWindow)
	}
	return term.LastSyncedAt.Add(-syncOverlapWindow)
}

// syncTerm busca no DJEN tudo que é novo pra term desde a última
// sincronização, grava (publicação + match, deduplicados via ON CONFLICT
// DO NOTHING) e publica diario_oficial.publication.matched pra cada
// casamento REALMENTE novo. Retorna quantos matches novos foram
// encontrados.
func (s *Service) syncTerm(ctx context.Context, term domain.MonitoredTerm) (int, error) {
	now := time.Now()
	since := syncSinceDate(term, now)

	// A busca (rede) acontece TODA fora de qualquer transação — o mesmo
	// cuidado que ProcessJob já toma com Check: uma chamada de rede lenta
	// nunca deveria segurar uma transação de banco aberta.
	var items []domain.SearchResultItem
	for page := 1; page <= maxSyncPagesPerTerm; page++ {
		result, err := s.client.Search(ctx, term.ToSearchQuery(&since, page, 0))
		if err != nil {
			return 0, fmt.Errorf("diario_oficial: search term %s: %w", term.ID, err)
		}
		items = append(items, result.Items...)
		if len(result.Items) == 0 {
			break
		}
	}

	newMatchEvents := make([]publicationMatchedPayload, 0)
	txErr := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		for _, item := range items {
			pub := domain.Publication{
				ID:                  uuid.New(),
				ExternalID:          item.ExternalID,
				Tribunal:            item.Tribunal,
				Orgao:               item.Orgao,
				TipoComunicacao:     item.TipoComunicacao,
				Texto:               item.Texto,
				ProcessNumber:       item.ProcessNumber,
				ProcessNumberMasked: item.ProcessNumberMasked,
				AvailabilityDate:    item.AvailabilityDate,
				Link:                item.Link,
				RawPayload:          item.RawPayload,
				CreatedAt:           now,
			}
			storedID, _, err := s.repo.UpsertPublication(ctx, tx, pub)
			if err != nil {
				return err
			}
			isNewMatch, err := s.repo.CreateMatch(ctx, tx, storedID, term.ID)
			if err != nil {
				return err
			}
			if isNewMatch {
				newMatchEvents = append(newMatchEvents, publicationMatchedPayload{
					MonitoredTermID:    term.ID,
					MonitoredTermLabel: term.Label,
					PublicationID:      storedID,
					Tribunal:           item.Tribunal,
					TipoComunicacao:    item.TipoComunicacao,
					ProcessNumber:      item.ProcessNumberMasked,
				})
			}
		}
		if err := s.repo.UpdateLastSyncedAt(ctx, tx, term.ID, now); err != nil {
			return err
		}
		for _, payload := range newMatchEvents {
			if err := s.outboxWriter.Write(ctx, tx, EventPublicationMatched, "diario_oficial_publication_match", payload.PublicationID.String(), uuid.New(), payload); err != nil {
				return err
			}
		}
		return nil
	})
	if txErr != nil {
		return 0, fmt.Errorf("diario_oficial: persist sync results for term %s: %w", term.ID, txErr)
	}

	return len(newMatchEvents), nil
}

// publicationMatchedPayload é o corpo do evento
// diario_oficial.publication.matched — espelha application.
// scanCompletedPayload no módulo scanning: só o resumo que o frontend
// precisa pra montar um toast, não a publicação inteira (quem quiser o
// texto completo consulta GET .../publications).
type publicationMatchedPayload struct {
	MonitoredTermID    uuid.UUID `json:"monitored_term_id"`
	MonitoredTermLabel string    `json:"monitored_term_label"`
	PublicationID      uuid.UUID `json:"publication_id"`
	Tribunal           string    `json:"tribunal"`
	TipoComunicacao    string    `json:"tipo_comunicacao"`
	ProcessNumber      string    `json:"process_number"`
}
