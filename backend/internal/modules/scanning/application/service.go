// Package application implementa o caso de uso do módulo scanning: rodar
// um CodeScanner registrado contra um alvo e persistir os achados.
//
// Fase 1 do roadmap de segurança (docs/roadmap-secops-orchestrator.md) só
// pede a fundação — nenhum scanner real (Trivy, Semgrep, TruffleHog,
// SonarQube, OWASP ZAP) ainda existe, e nenhum transport/HTTP endpoint ou
// worker/RabbitMQ chama isto. Por isso RunScan aqui é SÍNCRONO — grava
// achados + evento de outbox numa única transação e retorna, ao contrário
// do padrão job+outbox+worker assíncrono usado por
// diario_oficial.Service.CreateTestJob. Esse padrão assíncrono existe para
// desacoplar uma requisição HTTP de uma operação lenta/externa através de
// uma fila; sem nenhum endpoint ou consumer real ainda amarrado a isto,
// construir a fila/worker agora só criaria infraestrutura morta —
// mensagens publicadas que nada consome, ou um endpoint fictício só para
// justificar a fila. A Fase 2, ao introduzir o primeiro scanner real (uma
// execução potencialmente lenta, disparada por HTTP), é o momento correto
// de revisitar isto e decidir se RunScan continua síncrono ou migra para o
// padrão assíncrono já estabelecido no restante da plataforma.
package application

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

// EventScanCompleted é publicado no outbox toda vez que RunScan termina
// com sucesso, com ou sem achados — quem consumir este evento (hoje,
// ninguém; a Fase 2 introduz o primeiro consumer real, ex.: notificar via
// WebSocket) decide se achados CRITICAL/HIGH merecem alguma reação.
const EventScanCompleted = "scanning.scan.completed"

// scanCompletedPayload é o corpo do evento — só o necessário para
// localizar a execução, não os achados inteiros (esses vivem em
// scan_findings, consultáveis por scan_id).
type scanCompletedPayload struct {
	ScanID        uuid.UUID `json:"scan_id"`
	Scanner       string    `json:"scanner"`
	Target        string    `json:"target"`
	FindingsCount int       `json:"findings_count"`
}

// Service orquestra execuções de scan. scanners mapeia o nome de cada
// CodeScanner registrado (Strategy Pattern) ao seu Name() — o mesmo
// desenho de registro em mapa que o restante da plataforma já usa (ex.:
// lib/integrations/registry.ts no frontend), para que adicionar um
// scanner novo signifique registrar mais uma entrada, nunca alterar
// RunScan.
type Service struct {
	db           *pgxpool.Pool
	repo         domain.Repository
	outboxWriter *outbox.Writer
	audit        *audit.Writer
	scanners     map[string]domain.CodeScanner
	logger       *slog.Logger
}

// NewService constrói o Service a partir da lista de scanners disponíveis.
// Registrar dois scanners com o mesmo Name() é um erro de programação (bug
// de wiring, não uma condição de runtime a ser tolerada) e por isso
// entra em pânico imediatamente na inicialização, em vez de silenciosamente
// descartar um dos dois.
func NewService(
	db *pgxpool.Pool,
	repo domain.Repository,
	outboxWriter *outbox.Writer,
	auditWriter *audit.Writer,
	logger *slog.Logger,
	scanners ...domain.CodeScanner,
) *Service {
	byName := make(map[string]domain.CodeScanner, len(scanners))
	for _, s := range scanners {
		if _, exists := byName[s.Name()]; exists {
			panic(fmt.Sprintf("scanning: duplicate scanner registered: %q", s.Name()))
		}
		byName[s.Name()] = s
	}
	return &Service{
		db:           db,
		repo:         repo,
		outboxWriter: outboxWriter,
		audit:        auditWriter,
		scanners:     byName,
		logger:       logger,
	}
}

// RunScan executa o CodeScanner chamado scannerName contra target,
// persiste os achados e o evento scanning.scan.completed atomicamente, e
// retorna os achados encontrados. requestedBy é opcional (nil para
// execuções sem um usuário autenticado por trás, ex.: um futuro
// agendamento automático).
func (s *Service) RunScan(ctx context.Context, scannerName, target string, correlationID uuid.UUID, requestedBy *uuid.UUID) ([]domain.Finding, error) {
	scanner, ok := s.scanners[scannerName]
	if !ok {
		return nil, apperrors.NotFound(fmt.Sprintf("scanner %q not registered", scannerName))
	}

	findings, err := scanner.Execute(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scanning: execute %q against %q: %w", scannerName, target, err)
	}

	scanID := uuid.New()
	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.repo.SaveFindings(ctx, tx, scanID, scannerName, target, findings); err != nil {
			return err
		}
		payload := scanCompletedPayload{ScanID: scanID, Scanner: scannerName, Target: target, FindingsCount: len(findings)}
		return s.outboxWriter.Write(ctx, tx, EventScanCompleted, "scan", scanID.String(), correlationID, payload)
	})
	if err != nil {
		return nil, fmt.Errorf("scanning: persist scan %s: %w", scanID, err)
	}

	s.logger.Info("scanning: scan completed",
		slog.String("scan_id", scanID.String()), slog.String("scanner", scannerName),
		slog.String("target", target), slog.Int("findings", len(findings)))

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionScanCompleted,
			ResourceType:  "scan",
			ResourceID:    scanID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"scanner": scannerName, "target": target, "findings_count": len(findings)},
		})
	}

	return findings, nil
}
