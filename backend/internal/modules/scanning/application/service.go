// Package application implementa os casos de uso do módulo scanning:
// rodar um ou mais CodeScanner registrados contra um alvo e persistir os
// achados, tanto de forma síncrona (RunScan) quanto assíncrona via o
// padrão job+outbox+worker (CreateScanJob/ProcessScanJob/
// HandleScanDeadLetter) já estabelecido por diario_oficial.Service.
//
// Fase 1 do roadmap de segurança (docs/roadmap-secops-orchestrator.md) só
// construiu a fundação síncrona — sem nenhum scanner real registrado e sem
// nenhum endpoint HTTP amarrado a isto, o padrão assíncrono teria sido
// infraestrutura morta. A fase seguinte introduziu o primeiro scanner real
// (scanning/infrastructure.TrivyScanner: clona um repositório via git e
// escaneia dependências/Dockerfiles) — uma operação de segundos a minutos,
// disparada por um endpoint HTTP de verdade — e é isso que agora justifica
// o par CreateScanJob/ProcessScanJob: a requisição HTTP retorna 202
// imediatamente, e o clone+scan em si roda no worker, sem bloquear a
// requisição original. RunScan continua existindo, síncrono, como o modo
// de chamar um scanner diretamente sem depender de fila nenhuma — útil
// para testes e para uma futura execução agendada que já roda no worker.
//
// Fase 7 (Orquestração concorrente) adicionou a capacidade de um único
// job rodar VÁRIOS scanners em paralelo contra o mesmo alvo — ver
// runConcurrently/ProcessScanJob.
package application

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/domain/pagination"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
	"github.com/yurythx/nix-platform/internal/platform/database"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/outbox"
)

const (
	// JobType identifica todo job assíncrono deste módulo em jobs.Job.Type
	// — um único tipo cobre qualquer combinação de scanners registrados (a
	// lista de fato executada vive no payload do job, não no tipo), então
	// adicionar um scanner novo nunca exige um JobType novo.
	JobType = "scanning.scan"

	// EventScanRequested dispara ProcessScanJob no worker — o mesmo papel
	// que diario_oficial.job.created tem para aquele módulo.
	EventScanRequested = "scanning.scan.requested"

	// EventScanCompleted é publicado toda vez que um scan termina com pelo
	// menos um scanner bem-sucedido, com ou sem achados — tanto pelo
	// caminho síncrono (RunScan) quanto pelo assíncrono (ProcessScanJob).
	// Quem consumir este evento (hoje: só o WebSocket de notificação)
	// decide se achados CRITICAL/HIGH merecem alguma reação adicional.
	EventScanCompleted = "scanning.scan.completed"

	// EventScanFailed é publicado só quando o RabbitMQ já esgotou os
	// retries de um job de scan (ver HandleScanDeadLetter) — o mesmo
	// desenho de diario_oficial.job.failed: uma falha isolada, que ainda
	// pode ter sucesso numa nova tentativa, nunca gera este evento.
	EventScanFailed = "scanning.scan.failed"
)

// scanCompletedPayload é o corpo do evento EventScanCompleted — só o
// necessário para localizar a execução, não os achados inteiros (esses
// vivem em scan_findings, consultáveis por scan_id via ListFindings).
// Scanners lista só os que tiveram sucesso — os que falharam (se algum) só
// aparecem nos metadados de auditoria, não neste evento.
type scanCompletedPayload struct {
	ScanID        uuid.UUID `json:"scan_id"`
	Scanners      []string  `json:"scanners"`
	Target        string    `json:"target"`
	FindingsCount int       `json:"findings_count"`
}

// scanJobPayload é o corpo persistido em jobs.Job.Payload para um job de
// scan — a lista de scanners e o alvo que ProcessScanJob precisa pra saber
// o que executar quando o worker pegar o evento EventScanRequested.
type scanJobPayload struct {
	Scanners []string `json:"scanners"`
	Target   string   `json:"target"`
	// ProjectID (Fase 10) é preenchido quando este scan foi disparado a
	// partir de um domain.Project — nil pro fluxo avulso de sempre
	// (target digitado na hora, sem projeto nenhum por trás). Um projeto
	// GIT continua preenchendo Target normalmente (ProcessScanJob nem
	// precisa saber que existe um projeto, exceto pra registrar o
	// histórico); um projeto UPLOAD deixa Target vazio — é esse par
	// (ProjectID != nil && Target == "") que ProcessScanJob usa pra
	// decidir extrair o .zip em vez de clonar um alvo git (ver
	// runConcurrentlyLocal).
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	// LegacyScanner só existe pra decodificar jobs de ANTES da Fase 7
	// (Orquestração concorrente): o payload de um job de scan guardava
	// um scanner só, na chave singular "scanner", não a lista
	// "scanners" de hoje. Nenhum código novo grava mais nesta chave —
	// só projectScanStatus lê, como fallback, pra jobs antigos de
	// verdade que ainda existem neste ambiente não aparecerem com
	// requested_scanners vazio/nulo (ver TestProjectScanStatus_
	// LegacySingularScannerPayload_FallsBackCorrectly).
	LegacyScanner string `json:"scanner,omitempty"`
}

// jobRefPayload é o corpo do evento EventScanRequested/EventScanFailed —
// só o bastante pra quem consumir localizar o job de novo (o resto do
// estado vive na tabela jobs), mesmo desenho de
// diario_oficial/application/service.go's jobPayload.
type jobRefPayload struct {
	JobID uuid.UUID `json:"job_id"`
}

// Service orquestra execuções de scan. scanners mapeia o nome de cada
// CodeScanner registrado (Strategy Pattern) ao seu Name() — o mesmo
// desenho de registro em mapa que o restante da plataforma já usa (ex.:
// lib/integrations/registry.ts no frontend), para que adicionar um
// scanner novo signifique registrar mais uma entrada, nunca alterar
// RunScan/ProcessScanJob.
type Service struct {
	db           *pgxpool.Pool
	repo         domain.Repository
	jobsRepo     *jobs.Repository
	outboxWriter *outbox.Writer
	audit        *audit.Writer
	scanners     map[string]domain.CodeScanner
	// zipExtractor extrai um Project.UploadZip (Fase 10) pro volume
	// compartilhado — só usado por ProcessScanJob quando um job de scan
	// pertence a um projeto criado por upload. domain.ZipExtractor, não
	// *infrastructure.ZipExtractor: application nunca importa
	// infrastructure (Inversão de Dependência), mesmo princípio que já
	// vale pra domain.Repository/domain.CodeScanner.
	zipExtractor domain.ZipExtractor
	// flags/noiseFilterPatterns (Fase 13) controlam o filtro de ruído por
	// caminho — flags pode ficar nil (mesmo princípio de
	// diario_oficial.Service.flags): a checagem de feature flag é pulada
	// e o filtro nunca é aplicado, mantendo testes de aplicação que não
	// se importam com feature flags simples de escrever.
	flags               configflags.Store
	noiseFilterPatterns []string
	logger              *slog.Logger
}

// NewService constrói o Service a partir da lista de scanners disponíveis.
// Registrar dois scanners com o mesmo Name() é um erro de programação (bug
// de wiring, não uma condição de runtime a ser tolerada) e por isso
// entra em pânico imediatamente na inicialização, em vez de silenciosamente
// descartar um dos dois.
func NewService(
	db *pgxpool.Pool,
	repo domain.Repository,
	jobsRepo *jobs.Repository,
	outboxWriter *outbox.Writer,
	auditWriter *audit.Writer,
	zipExtractor domain.ZipExtractor,
	flags configflags.Store,
	noiseFilterPatterns []string,
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
		db:                  db,
		repo:                repo,
		jobsRepo:            jobsRepo,
		outboxWriter:        outboxWriter,
		audit:               auditWriter,
		zipExtractor:        zipExtractor,
		flags:               flags,
		noiseFilterPatterns: noiseFilterPatterns,
		scanners:            byName,
		logger:              logger,
	}
}

// noiseFilterEnabled consulta NoiseFilterFlagKey — mesmo padrão de
// diario_oficial.Service.CreateTestJob (s.flags nil pula a checagem,
// tratado como desligado, já que "mostrar tudo" é o comportamento seguro
// por padrão desta fase).
func (s *Service) noiseFilterEnabled(ctx context.Context) bool {
	if s.flags == nil {
		return false
	}
	enabled, err := s.flags.IsEnabled(ctx, NoiseFilterFlagKey, false)
	if err != nil {
		s.logger.Warn("scanning: failed to check noise filter flag (defaulting to showing everything)", slog.Any("error", err))
		return false
	}
	return enabled
}

// RunScan executa o CodeScanner chamado scannerName contra target,
// persiste os achados e o evento EventScanCompleted atomicamente, e
// retorna os achados encontrados. Bloqueia até o scanner terminar — para
// um scanner potencialmente lento chamado a partir de HTTP, prefira
// CreateScanJob (que também roda vários scanners em paralelo, ver
// ProcessScanJob; RunScan continua limitado a um só, já que quem chama
// direto — testes, uma futura execução agendada — controla exatamente
// qual scanner quer, sem precisar do desenho de job/orquestração).
// requestedBy é opcional (nil para execuções sem um usuário autenticado
// por trás). scanID retornado é o mesmo usado para consultar depois via
// ListFindings — RunScan gera um novo a cada chamada, já que (ao
// contrário de CreateScanJob/ProcessScanJob) não há nenhum jobID
// pré-existente para reaproveitar.
func (s *Service) RunScan(ctx context.Context, scannerName, target string, correlationID uuid.UUID, requestedBy *uuid.UUID) (scanID uuid.UUID, findings []domain.Finding, err error) {
	scanner, ok := s.scanners[scannerName]
	if !ok {
		return uuid.Nil, nil, apperrors.NotFound(fmt.Sprintf("scanner %q not registered", scannerName))
	}

	findings, err = scanner.Execute(ctx, target)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("scanning: execute %q against %q: %w", scannerName, target, err)
	}
	packages := inventoryFor(ctx, scanner, target, &err)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("scanning: inventory %q against %q: %w", scannerName, target, err)
	}

	scanID = uuid.New()
	outcome := scannerOutcome{scanner: scannerName, findings: findings, packages: packages}
	if err := s.persistCompletion(ctx, scanID, target, correlationID, []scannerOutcome{outcome}); err != nil {
		return uuid.Nil, nil, err
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionScanCompleted,
			ResourceType:  "scan",
			ResourceID:    scanID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"scanners": []string{scannerName}, "target": target, "findings_count": len(findings)},
		})
	}

	return scanID, findings, nil
}

// scannerOutcome é o resultado da execução de um scanner contra um alvo —
// exatamente um erro OU achados/pacotes (nunca erro junto com um dos dois),
// usado tanto pelo caminho síncrono (RunScan, sempre uma lista de um)
// quanto pelo assíncrono (ProcessScanJob via runConcurrently, uma lista de
// N). packages só é populado por um scanner que também implementa
// domain.InventoryProvider (Fase 11 — hoje só Syft); a maioria dos
// scanners nunca preenche este campo.
type scannerOutcome struct {
	scanner  string
	findings []domain.Finding
	packages []domain.Package
	err      error
}

// persistCompletion grava os achados de todo scanner bem-sucedido em
// outcomes (os que falharam são pulados — sem achado nenhum pra gravar) +
// o evento EventScanCompleted, tudo numa única transação — o miolo
// compartilhado entre RunScan e ProcessScanJob, para as duas nunca
// divergirem em como um scan concluído é registrado. Não é chamado se
// TODOS os scanners de outcomes falharam (ver ProcessScanJob) — gravar um
// EventScanCompleted sem nenhum sucesso seria enganoso.
func (s *Service) persistCompletion(ctx context.Context, scanID uuid.UUID, target string, correlationID uuid.UUID, outcomes []scannerOutcome) error {
	var succeededNames []string
	totalFindings := 0

	err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		for _, o := range outcomes {
			if o.err != nil {
				continue
			}
			if err := s.repo.SaveFindings(ctx, tx, scanID, o.scanner, target, o.findings); err != nil {
				return err
			}
			// SavePackages (Fase 11 — Syft): mesma atomicidade de
			// SaveFindings, dentro da mesma transação — um scan concluído
			// nunca fica com achados gravados e inventário perdido, ou
			// vice-versa. Um outcome sem pacotes (todo scanner exceto
			// Syft) é um no-op (ver packages_repository.go).
			if err := s.repo.SavePackages(ctx, tx, scanID, o.packages); err != nil {
				return err
			}
			succeededNames = append(succeededNames, o.scanner)
			totalFindings += len(o.findings)
		}
		payload := scanCompletedPayload{ScanID: scanID, Scanners: succeededNames, Target: target, FindingsCount: totalFindings}
		return s.outboxWriter.Write(ctx, tx, EventScanCompleted, "scan", scanID.String(), correlationID, payload)
	})
	if err != nil {
		return fmt.Errorf("scanning: persist scan %s: %w", scanID, err)
	}

	s.logger.Info("scanning: scan completed",
		slog.String("scan_id", scanID.String()), slog.Any("scanners", succeededNames),
		slog.String("target", target), slog.Int("findings", totalFindings))
	return nil
}

// ListFindings retorna todo achado de uma execução de scan, mais
// severo/recente primeiro — menos os que baterem com o filtro de ruído
// (Fase 13), se a feature flag NoiseFilterFlagKey estiver ligada.
func (s *Service) ListFindings(ctx context.Context, scanID uuid.UUID) ([]domain.PersistedFinding, error) {
	findings, err := s.repo.ListByScanID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list findings for scan %s: %w", scanID, err)
	}
	if s.noiseFilterEnabled(ctx) {
		findings = filterNoise(findings, s.noiseFilterPatterns)
	}
	return findings, nil
}

// ListPackages retorna o inventário (Fase 11 — Syft) de uma execução de
// scan, ordem alfabética de nome. Uma lista vazia (scan sem Syft, ou Syft
// não achou nenhum pacote) não é erro — mesmo princípio de ListFindings
// devolver uma lista vazia pra um scan limpo.
func (s *Service) ListPackages(ctx context.Context, scanID uuid.UUID) ([]domain.Package, error) {
	packages, err := s.repo.ListPackagesByScanID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("scanning: list packages for scan %s: %w", scanID, err)
	}
	return packages, nil
}

// ScanStatus é a projeção de um job de scan pensada pra consumo HTTP (ver
// GetScanStatus/transport.GetScanStatus) — o mesmo Status/Attempts/
// timestamps que jobs.Job já guarda, mais os campos específicos de
// scanning (scanners pedidos, quais tiveram sucesso, o detalhe
// estruturado de quem falhou e por quê) decodificados de dentro de
// Payload/Result/Error — só esta package sabe o formato scanning-specific
// desses três campos genéricos.
//
// Existe porque, antes desta mudança, um scan que falhava (parcial ou
// totalmente) não tinha NENHUMA superfície HTTP pra consultar o motivo:
// só aparecia no log do worker. FailedScanners é o que responde
// diretamente ao pedido do usuário de saber "qual ferramenta achou o
// erro" (Scanner) "com descrição de que tipo de erro" (Code, Message) —
// "como corrigir" fica por conta de quem exibe isso (ver
// transport.remediationHint), não deste tipo: uma sugestão de correção é
// texto de apresentação, não um dado que faça sentido persistir junto do
// job.
type ScanStatus struct {
	JobID  uuid.UUID
	Status string
	Target string
	// ProjectID (Fase 10) — nil pra um scan avulso, preenchido quando
	// este job foi disparado a partir de um domain.Project (ver
	// scanJobPayload.ProjectID). ListProjectScans filtra por este campo.
	ProjectID         *uuid.UUID
	RequestedScanners []string
	SucceededScanners []string
	FailedScanners    []domain.ScannerFailure
	// ScannerRuns dá o progresso de CADA scanner individualmente — ao
	// contrário de Status (o job como um todo), funciona mesmo enquanto
	// o job ainda está "processing": é o que permite um painel mostrar
	// qual scanner está rodando agora e quanto falta, em vez de só
	// "processing" sem mais detalhe até tudo terminar de uma vez.
	ScannerRuns []domain.ScannerRun
	Attempts    int
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
}

// GetScanStatus consulta o estado atual de um job de scan — quem chama
// tipicamente é a UI logo depois de disparar um scan (CreateScanJob),
// fazendo polling até o status virar terminal (completed/failed/
// dead_letter), pra saber se precisa mostrar os achados, um aviso de
// falha parcial, ou o motivo de uma falha total.
func (s *Service) GetScanStatus(ctx context.Context, jobID uuid.UUID) (*ScanStatus, error) {
	job, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("scanning: get scan status %s: %w", jobID, err)
	}
	return s.projectScanStatus(ctx, job)
}

// projectScanStatus é o miolo compartilhado entre GetScanStatus (um job
// já carregado por ID) e ListRecentScans (uma página inteira de jobs) —
// as duas nunca divergem em como um *jobs.Job vira um *ScanStatus.
func (s *Service) projectScanStatus(ctx context.Context, job *jobs.Job) (*ScanStatus, error) {
	jobID := job.ID
	var payload scanJobPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("scanning: decode job %s payload: %w", jobID, err)
	}
	requestedScanners := payload.Scanners
	if len(requestedScanners) == 0 && payload.LegacyScanner != "" {
		requestedScanners = []string{payload.LegacyScanner}
	}

	status := &ScanStatus{
		JobID:             job.ID,
		Status:            string(job.Status),
		Target:            payload.Target,
		ProjectID:         payload.ProjectID,
		RequestedScanners: requestedScanners,
		Attempts:          job.Attempts,
		CreatedAt:         job.CreatedAt,
		StartedAt:         job.StartedAt,
		FinishedAt:        job.FinishedAt,
	}

	switch job.Status {
	case jobs.StatusCompleted:
		var result struct {
			SucceededScanners []string                `json:"succeeded_scanners"`
			FailedScanners    []domain.ScannerFailure `json:"failed_scanners,omitempty"`
		}
		if len(job.Result) > 0 {
			if err := json.Unmarshal(job.Result, &result); err != nil {
				// Compatibilidade com jobs concluídos ANTES desta fase:
				// failed_scanners costumava ser só uma lista de nomes
				// (strings), não domain.ScannerFailure estruturado — cai
				// pra esse formato antigo em vez de quebrar a consulta
				// inteira por causa de um job velho (confirmado contra um
				// job de verdade deste ambiente, b2a39c9c..., completado
				// antes desta mudança). A tentativa acima pode ter
				// deixado result.FailedScanners parcialmente preenchido
				// com valores zero antes de falhar (um detalhe de como
				// encoding/json decodifica um array elemento por
				// elemento) — por isso ATRIBUI abaixo, nunca append,
				// pra nunca herdar esse lixo parcial.
				var legacy struct {
					SucceededScanners []string `json:"succeeded_scanners"`
					FailedScanners    []string `json:"failed_scanners,omitempty"`
				}
				if legacyErr := json.Unmarshal(job.Result, &legacy); legacyErr != nil {
					return nil, fmt.Errorf("scanning: decode job %s result: %w", jobID, err)
				}
				failed := make([]domain.ScannerFailure, len(legacy.FailedScanners))
				for i, name := range legacy.FailedScanners {
					failed[i] = domain.ScannerFailure{Scanner: name}
				}
				result.SucceededScanners = legacy.SucceededScanners
				result.FailedScanners = failed
			}
		}
		status.SucceededScanners = result.SucceededScanners
		status.FailedScanners = result.FailedScanners
		if len(status.SucceededScanners) == 0 && len(status.FailedScanners) == 0 && len(requestedScanners) > 0 {
			// jobs.result de jobs completados ANTES até do formato
			// legado acima (nem succeeded_scanners nem failed_scanners
			// gravados — só findings_count, confirmado contra jobs de
			// verdade deste ambiente) não tem como saber QUAL scanner
			// teve sucesso a partir do que foi persistido. Mas
			// status==completed já implica que pelo menos um teve, e
			// nenhuma falha foi registrada — a inferência mais honesta
			// é que todo scanner pedido teve sucesso, não deixar a
			// lista vazia (que a UI leria como "nenhum scanner rodou",
			// falso pra um job concluído de verdade).
			status.SucceededScanners = requestedScanners
		}
	case jobs.StatusFailed, jobs.StatusDeadLetter:
		if job.Error != nil && *job.Error != "" {
			status.FailedScanners = decodeFailures(*job.Error)
		}
	}

	// Best-effort: funciona pra QUALQUER status (inclusive "processing",
	// o caso que realmente importa pro painel de progresso) — uma falha
	// aqui não derruba a resposta inteira, já que ScannerRuns é
	// informação suplementar, não o resultado principal do job.
	if runs, err := s.repo.ListScannerRuns(ctx, jobID); err != nil {
		s.logger.Warn("scanning: failed to load scanner progress (best-effort, status still returned)",
			slog.String("job_id", jobID.String()), slog.Any("error", err))
	} else {
		status.ScannerRuns = runs
	}

	return status, nil
}

// maxRecentScans é o teto de ListRecentScans — mesmo espírito de
// maxRecentFindings logo abaixo (uma consulta "generosa demais" ainda é
// atendida, só que com o teto em vez do valor pedido).
const maxRecentScans = 100

// ListRecentScans retorna os jobs de scan mais recentes, mais novo
// primeiro — o que /seguranca usa pra listar "resultados separados por
// scan" (cada job/execução como sua própria entrada, em vez de um feed
// só de achados misturando todo scan junto). Reaproveita o mesmo
// projeção de GetScanStatus pra cada job da página, então as duas
// consultas nunca divergem em formato.
func (s *Service) ListRecentScans(ctx context.Context, limit int) ([]*ScanStatus, error) {
	if limit <= 0 || limit > maxRecentScans {
		limit = maxRecentScans
	}

	jobList, _, err := s.jobsRepo.List(ctx, pagination.New(1, limit, maxRecentScans), JobType)
	if err != nil {
		return nil, fmt.Errorf("scanning: list recent scans: %w", err)
	}

	out := make([]*ScanStatus, 0, len(jobList))
	for _, job := range jobList {
		status, err := s.projectScanStatus(ctx, job)
		if err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	return out, nil
}

// ListProjectScans retorna as execuções mais recentes de UM projeto, mais
// nova primeiro (Fase 10) — filtra dentro de ListRecentScans (mesma
// consulta, mesmo teto maxRecentScans) por ScanStatus.ProjectID, em vez de
// uma consulta nova no banco: scanJobPayload.ProjectID vive dentro do
// JSONB do payload de jobs.Job, não numa coluna própria (o volume de
// scans desta plataforma nunca justificou um índice dedicado só pra
// isto). Uma lista vazia (projeto nunca escaneado) não é erro.
func (s *Service) ListProjectScans(ctx context.Context, projectID uuid.UUID) ([]*ScanStatus, error) {
	scans, err := s.ListRecentScans(ctx, maxRecentScans)
	if err != nil {
		return nil, err
	}
	out := make([]*ScanStatus, 0)
	for _, sc := range scans {
		if sc.ProjectID != nil && *sc.ProjectID == projectID {
			out = append(out, sc)
		}
	}
	return out, nil
}

// ProjectFindingHistory (Fase 12 — deduplicação por fingerprint) é UM
// achado deduplicado ENTRE re-scans do MESMO projeto — nunca dentro de um
// scan só (cada linha de scan_findings já é um achado distinto por
// natureza, ver domain.Fingerprint). Representa a pergunta "esse mesmo
// problema já apareceu antes, nesse projeto, e ainda está presente?" —
// nunca respondida antes desta fase (só dava pra ver achados por scan
// individual, um de cada vez).
type ProjectFindingHistory struct {
	Fingerprint   string
	Scanner       string
	OWASPCategory string
	Severity      domain.Severity
	Description   string
	File          string
	Line          int
	// FirstSeenAt/LastSeenAt são MIN/MAX(created_at) entre toda ocorrência
	// deste fingerprint nos scans do projeto — "apareceu pela primeira vez
	// em X, ainda presente em Y" (o pedido literal do roadmap).
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	// ScanCount é quantos scans DISTINTOS deste projeto incluíram este
	// fingerprint — não quantas linhas de scan_findings (nunca deveria
	// duplicar dentro de um scan só, mas contado por scan mesmo assim,
	// nunca por linha, pra nunca inflar por acidente se algum dia
	// duplicar).
	ScanCount int
	// StillPresent indica se este fingerprint aparece no scan MAIS
	// RECENTE do projeto — a UI usa isto pra separar "ainda um problema"
	// de "já foi corrigido, só ficou no histórico".
	StillPresent bool
}

// ListProjectFindingsHistory agrupa por Fingerprint todo achado de TODOS
// os scans de um projeto (Fase 12) — reaproveita ListProjectScans (mesma
// consulta que já filtra por projeto) pra saber quais scan_ids pertencem
// a ele, busca os achados desses scans numa viagem só
// (repo.ListByScanIDs) e agrupa em memória: o volume de achados por
// projeto nesta plataforma nunca justificou um GROUP BY no banco pra
// isto. Uma lista vazia (projeto nunca escaneado, ou sem achado nenhum
// em nenhum scan) não é erro.
func (s *Service) ListProjectFindingsHistory(ctx context.Context, projectID uuid.UUID) ([]ProjectFindingHistory, error) {
	scans, err := s.ListProjectScans(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if len(scans) == 0 {
		return nil, nil
	}
	// scans[0] é o mais recente — ListProjectScans preserva a ordem de
	// ListRecentScans (ORDER BY created_at DESC), só filtrando por
	// projeto.
	mostRecentScanID := scans[0].JobID

	scanIDs := make([]uuid.UUID, len(scans))
	for i, sc := range scans {
		scanIDs[i] = sc.JobID
	}

	findings, err := s.repo.ListByScanIDs(ctx, scanIDs)
	if err != nil {
		return nil, fmt.Errorf("scanning: list findings history for project %s: %w", projectID, err)
	}
	// Filtro de ruído (Fase 13), aplicado ANTES do agrupamento por
	// fingerprint — um achado de ruído nunca conta pra ScanCount/
	// FirstSeenAt/LastSeenAt de nenhum grupo.
	if s.noiseFilterEnabled(ctx) {
		findings = filterNoise(findings, s.noiseFilterPatterns)
	}

	type group struct {
		entry     ProjectFindingHistory
		scansSeen map[uuid.UUID]bool
	}
	groups := make(map[string]*group)
	var order []string
	for _, f := range findings {
		g, ok := groups[f.FindingFingerprint]
		if !ok {
			g = &group{
				entry: ProjectFindingHistory{
					Fingerprint:   f.FindingFingerprint,
					Scanner:       f.Scanner,
					OWASPCategory: f.OWASPCategory,
					Severity:      f.Severity,
					Description:   f.Description,
					File:          f.File,
					Line:          f.Line,
					FirstSeenAt:   f.CreatedAt,
					LastSeenAt:    f.CreatedAt,
				},
				scansSeen: make(map[uuid.UUID]bool),
			}
			groups[f.FindingFingerprint] = g
			order = append(order, f.FindingFingerprint)
		}
		if f.CreatedAt.Before(g.entry.FirstSeenAt) {
			g.entry.FirstSeenAt = f.CreatedAt
		}
		if f.CreatedAt.After(g.entry.LastSeenAt) {
			g.entry.LastSeenAt = f.CreatedAt
		}
		if f.ScanID == mostRecentScanID {
			g.entry.StillPresent = true
		}
		g.scansSeen[f.ScanID] = true
	}

	out := make([]ProjectFindingHistory, 0, len(order))
	for _, fp := range order {
		g := groups[fp]
		g.entry.ScanCount = len(g.scansSeen)
		out = append(out, g.entry)
	}

	// Ainda presente primeiro (o que precisa de atenção AGORA), depois
	// mais grave primeiro, depois mais recente primeiro — mesmo
	// raciocínio de findingSeverityOrder (postgres_repository.go), só que
	// em memória, já que este resultado nunca vem direto de uma única
	// query SQL.
	sort.Slice(out, func(i, j int) bool {
		if out[i].StillPresent != out[j].StillPresent {
			return out[i].StillPresent
		}
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	return out, nil
}

// severityRank dá a mesma ordem "mais grave primeiro" que
// findingSeverityOrder já usa em SQL (postgres_repository.go) — reescrita
// aqui em Go porque ListProjectFindingsHistory ordena em memória, não via
// ORDER BY.
func severityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 0
	case domain.SeverityHigh:
		return 1
	case domain.SeverityMedium:
		return 2
	default:
		return 3
	}
}

// decodeFailures decodifica o texto de jobs.error de volta em
// []domain.ScannerFailure — o formato que encodeFailures grava desde
// esta fase. Tolerante a texto que NÃO está nesse formato (o fallback
// defensivo de HandleScanDeadLetter grava só "max retries exceeded" em
// texto puro quando não há nenhum jobs.error anterior; um jobs.error
// gravado antes desta mudança também não seria JSON): em vez de devolver
// erro e quebrar GetScanStatus pra um job assim, devolve uma única
// entrada sintética com o texto bruto na Message — sempre alguma
// informação em vez de um erro de decodificação visível pro cliente
// HTTP.
func decodeFailures(raw string) []domain.ScannerFailure {
	var failures []domain.ScannerFailure
	if err := json.Unmarshal([]byte(raw), &failures); err != nil {
		return []domain.ScannerFailure{{Message: raw}}
	}
	return failures
}

// maxRecentFindings é o teto de ListRecentFindings — nenhum chamador
// consegue pedir mais que isso, nem passando um limit maior (evita uma
// consulta acidentalmente sem paginação nenhuma trazer a tabela inteira
// pro frontend de uma vez).
const maxRecentFindings = 200

// ListRecentFindings retorna os achados mais graves/recentes entre TODAS
// as execuções de scan — a Fase 9 (UI no frontend) usa isto pra listar
// achados sem exigir que quem chama já saiba um scan_id de antemão
// (diferente de ListFindings, escopado a um scan só). limit <= 0 usa um
// default razoável; limit > maxRecentFindings é truncado, nunca rejeitado
// com erro — um pedido "generoso demais" ainda é atendido, só que com o
// teto em vez do valor pedido.
func (s *Service) ListRecentFindings(ctx context.Context, limit int) ([]domain.PersistedFinding, error) {
	const defaultLimit = 50
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxRecentFindings {
		limit = maxRecentFindings
	}

	findings, err := s.repo.ListRecent(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("scanning: list recent findings: %w", err)
	}
	// Filtro de ruído (Fase 13) aplicado DEPOIS do limit — um achado
	// removido aqui pode deixar a resposta com menos de `limit` linhas
	// mesmo havendo mais achados não-ruído além da janela buscada; aceito
	// como o mesmo tipo de trade-off que qualquer filtro pós-consulta já
	// tem nesta plataforma (nunca justificou mover o filtro pro SQL só
	// por isso — configurável em runtime via feature flag, não vale a
	// complexidade de um WHERE dinâmico por padrão de caminho).
	if s.noiseFilterEnabled(ctx) {
		findings = filterNoise(findings, s.noiseFilterPatterns)
	}
	return findings, nil
}

// maxUploadZipBytes limita o tamanho do PRÓPRIO arquivo .zip aceito ao
// criar um projeto por upload (Fase 10) — diferente de
// infrastructure.maxZipUncompressedBytes (o teto do conteúdo
// DESCOMPRIMIDO, aplicado só na hora de escanear). Este teto aqui protege
// a gravação em si: Project.UploadZip vive numa coluna BYTEA do Postgres,
// e um blob sem limite nenhum seria seu próprio problema de capacidade,
// bem antes de qualquer scan rodar.
const maxUploadZipBytes = 50 * 1024 * 1024 // 50MB

// CreateProjectGit cria um domain.Project (Fase 10) apontando pra um alvo
// git — mesma filosofia de validação "preguiçosa" que um scan avulso já
// usa: só confere que target não é vazio aqui; o formato completo
// (https://, host não-privado) só é validado de verdade na hora de
// escanear (git_clone.go's parseGitTarget/validateHost, dentro do
// worker) — nunca duplicado aqui, pra nunca divergir entre as duas
// validações.
func (s *Service) CreateProjectGit(ctx context.Context, name, target string, requestedBy *uuid.UUID) (*domain.Project, error) {
	if name == "" {
		return nil, apperrors.Validation("name is required")
	}
	if target == "" {
		return nil, apperrors.Validation("target is required")
	}

	p := domain.Project{ID: uuid.New(), Name: name, SourceType: domain.ProjectSourceGit, Target: target, CreatedAt: time.Now()}
	if err := s.repo.CreateProject(ctx, p); err != nil {
		return nil, fmt.Errorf("scanning: create project: %w", err)
	}
	s.recordProjectCreated(ctx, p, requestedBy)
	return &p, nil
}

// recordProjectCreated grava a auditoria de um projeto novo (Fase 10) —
// achado de auditoria: CreateProjectGit/CreateProjectUpload não tinham
// nenhum registro, ao contrário de createScanJob (ActionScanRequested),
// mesmo criar um projeto por upload guardando até 50MB de código de
// terceiros. Best-effort (audit pode ser nil, mesmo princípio do resto
// do Service) — nunca falha a criação do projeto por conta disto.
func (s *Service) recordProjectCreated(ctx context.Context, p domain.Project, requestedBy *uuid.UUID) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, audit.Entry{
		UserID:       requestedBy,
		Action:       audit.ActionProjectCreated,
		ResourceType: "project",
		ResourceID:   p.ID.String(),
		Metadata:     map[string]any{"name": p.Name, "source_type": string(p.SourceType), "target": p.Target},
	})
}

// CreateProjectUpload cria um domain.Project (Fase 10) a partir dos bytes
// de um .zip — nunca extraído nem validado como zip aqui (isso só
// acontece de verdade na hora de escanear, ZipExtractor.ExtractZip,
// dentro do worker), mesmo princípio de CreateProjectGit acima: valida só
// o suficiente pra rejeitar entrada obviamente inválida cedo (vazio,
// grande demais), sem duplicar a validação de conteúdo que já vive em
// outro lugar.
func (s *Service) CreateProjectUpload(ctx context.Context, name string, zipBytes []byte, requestedBy *uuid.UUID) (*domain.Project, error) {
	if name == "" {
		return nil, apperrors.Validation("name is required")
	}
	if len(zipBytes) == 0 {
		return nil, apperrors.Validation("zip file is required")
	}
	if len(zipBytes) > maxUploadZipBytes {
		return nil, apperrors.Validation(fmt.Sprintf("zip file exceeds the %dMB limit", maxUploadZipBytes/(1024*1024)))
	}

	p := domain.Project{ID: uuid.New(), Name: name, SourceType: domain.ProjectSourceUpload, UploadZip: zipBytes, CreatedAt: time.Now()}
	if err := s.repo.CreateProject(ctx, p); err != nil {
		return nil, fmt.Errorf("scanning: create project: %w", err)
	}
	s.recordProjectCreated(ctx, p, requestedBy)
	return &p, nil
}

// maxProjectsList é o teto de ListProjects — mesmo espírito de
// maxRecentScans/maxRecentFindings.
const maxProjectsList = 100

// ListProjects retorna os projetos mais recentes primeiro.
func (s *Service) ListProjects(ctx context.Context, limit int) ([]domain.Project, error) {
	if limit <= 0 || limit > maxProjectsList {
		limit = maxProjectsList
	}
	projects, err := s.repo.ListProjects(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("scanning: list projects: %w", err)
	}
	return projects, nil
}

// GetProject busca um projeto por ID.
func (s *Service) GetProject(ctx context.Context, id uuid.UUID) (domain.Project, error) {
	p, err := s.repo.GetProject(ctx, id)
	if err != nil {
		return domain.Project{}, err
	}
	return p, nil
}

// CreateScanJob implementa o "Commit" do fluxo assíncrono avulso (sem
// projeto por trás) — mesmo desenho de diario_oficial.Service.
// CreateTestJob. Ver createScanJob pro que as duas variantes (esta e
// CreateProjectScanJob) compartilham.
func (s *Service) CreateScanJob(ctx context.Context, correlationID uuid.UUID, scannerNames []string, target string, requestedBy *uuid.UUID) (*jobs.Job, error) {
	if target == "" {
		return nil, apperrors.Validation("target is required")
	}
	return s.createScanJob(ctx, correlationID, scannerNames, target, nil, requestedBy)
}

// CreateProjectScanJob dispara um scan a partir de um domain.Project já
// existente (Fase 10) — "Rodar de novo" no frontend, sem pedir a URL/o
// .zip de novo. Resolve target a partir do projeto: um projeto GIT usa
// project.Target (o job resultante fica indistinguível de um scan avulso
// pro resto do pipeline, exceto por carregar ProjectID pro histórico); um
// projeto UPLOAD deixa Target vazio de propósito — é esse sinal que
// ProcessScanJob usa pra extrair o .zip em vez de clonar (ver
// runConcurrentlyLocal).
func (s *Service) CreateProjectScanJob(ctx context.Context, correlationID uuid.UUID, scannerNames []string, projectID uuid.UUID, requestedBy *uuid.UUID) (*jobs.Job, error) {
	project, err := s.repo.GetProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	target := project.Target
	if project.SourceType == domain.ProjectSourceUpload {
		// Nunca fica vazio, nem enquanto o job ainda está "queued": sem
		// isto, GetScanStatus/ListScans mostrariam Target="" pra um scan
		// de upload até ele terminar (só ProcessScanJob saberia o nome
		// "upload:<projeto>" de verdade) — computado aqui, na criação,
		// pra aparecer certo desde o primeiro instante.
		target = uploadTarget(project.Name)
	}
	return s.createScanJob(ctx, correlationID, scannerNames, target, &project, requestedBy)
}

// uploadTarget é o "alvo" sintético gravado pra um scan de projeto
// UPLOAD — nunca um alvo git de verdade, só um rótulo consistente
// (scan_findings.target, ScanStatus.Target, jobs.payload.target) que
// identifica de qual projeto esse scan veio, já que não existe URL
// nenhuma pra mostrar.
func uploadTarget(projectName string) string {
	return "upload:" + projectName
}

// createScanJob é o miolo compartilhado por CreateScanJob (avulso) e
// CreateProjectScanJob (Fase 10): valida que todo nome em scannerNames
// está registrado (e, pra um projeto UPLOAD, que cada um também
// implementa domain.LocalScanner — SonarQube/ZAP são rejeitados aqui,
// nunca silenciosamente ignorados nem descobertos como falha só depois
// que o worker já tentou), cria o job e seu evento de outbox disparador
// atomicamente, e retorna — quem chama (o transport) responde 202. O ID
// do job também é o scan_id usado depois em ListFindings, para que o
// cliente HTTP consiga consultar os achados de TODOS os scanners pedidos
// com o mesmo ID que recebeu na criação.
func (s *Service) createScanJob(ctx context.Context, correlationID uuid.UUID, scannerNames []string, target string, project *domain.Project, requestedBy *uuid.UUID) (*jobs.Job, error) {
	if len(scannerNames) == 0 {
		return nil, apperrors.Validation("at least one scanner is required")
	}

	isUpload := project != nil && project.SourceType == domain.ProjectSourceUpload

	var unknown, unsupported []string
	for _, name := range scannerNames {
		scanner, ok := s.scanners[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if isUpload {
			if _, ok := scanner.(domain.LocalScanner); !ok {
				unsupported = append(unsupported, name)
			}
		}
	}
	if len(unknown) > 0 {
		return nil, apperrors.NotFound(fmt.Sprintf("scanner(s) not registered: %s", strings.Join(unknown, ", ")))
	}
	if len(unsupported) > 0 {
		return nil, apperrors.Validation(fmt.Sprintf(
			"scanner(s) not supported for an upload-based project (need a git clone or a live URL): %s",
			strings.Join(unsupported, ", ")))
	}

	payload := scanJobPayload{Scanners: scannerNames, Target: target}
	if project != nil {
		payload.ProjectID = &project.ID
	}

	job, err := jobs.New(JobType, correlationID, payload)
	if err != nil {
		return nil, fmt.Errorf("scanning: build job: %w", err)
	}

	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.Create(ctx, tx, job); err != nil {
			return err
		}
		return s.outboxWriter.Write(ctx, tx, EventScanRequested, "job", job.ID.String(), correlationID, jobRefPayload{JobID: job.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("scanning: create scan job: %w", err)
	}

	if s.audit != nil {
		metadata := map[string]any{"scanners": scannerNames, "target": target}
		if project != nil {
			metadata["project_id"] = project.ID.String()
		}
		_ = s.audit.Record(ctx, audit.Entry{
			UserID:        requestedBy,
			Action:        audit.ActionScanRequested,
			ResourceType:  "job",
			ResourceID:    job.ID.String(),
			CorrelationID: &correlationID,
			Metadata:      metadata,
		})
	}

	return job, nil
}

// runConcurrently executa cada scanner em scannerNames contra target em
// paralelo (Fase 7 do roadmap — Orquestração concorrente), retornando o
// resultado de cada um na mesma ordem de scannerNames.
//
// O roadmap descreve isto como "goroutines + errgroup" — usa goroutines
// puras + sync.WaitGroup aqui, deliberadamente sem o pacote errgroup: o
// comportamento padrão de errgroup.Group.WithContext cancela o ctx do
// grupo inteiro assim que o primeiro Go() retorna erro, exatamente o
// oposto do que esta fase pede ("cancelando um scanner que trava sem
// derrubar os outros"). Evitar errgroup.WithContext aqui não é
// cosmético: é o que garante essa independência. Cada scanner já limita
// seu próprio tempo de execução por dentro (CloneTimeout do git,
// SonarQubeAnalysisTimeout, ZapScanTimeout, ...) — não precisa de mais um
// nível de timeout aqui, só isolamento: a falha ou lentidão de um nunca
// afeta os demais, porque cada goroutine roda de forma completamente
// independente e nenhuma jamais cancela o contexto de outra.
// jobID vira o progresso individual de cada scanner (StartScannerRun/
// FinishScannerRun, ver markScannerRunning/markScannerFinished abaixo) —
// o que GetScanStatus expõe pra dar visibilidade em tempo real de qual
// scanner está rodando agora e qual já terminou, pedido explícito do
// usuário ("um painel visual dos testes rodando... quero saber qual
// teste está rodando, quanto falta pra acabar"), sem o qual um job
// "processing" era uma caixa preta do início ao fim.
func (s *Service) runConcurrently(ctx context.Context, jobID uuid.UUID, scannerNames []string, target string) []scannerOutcome {
	outcomes := make([]scannerOutcome, len(scannerNames))
	var wg sync.WaitGroup
	for i, name := range scannerNames {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			scanner, ok := s.scanners[name]
			if !ok {
				// Defensivo: CreateScanJob já validou isto na criação do
				// job, mas um scanner poderia ter sido desregistrado
				// entre a criação e o processamento (ex.: um deploy). Não
				// é uma falha transitória do próprio scanner, mas ainda
				// assim é só a falha DESTE scanner — os demais continuam.
				err := fmt.Errorf("scanner %q not registered", name)
				outcomes[i] = scannerOutcome{scanner: name, err: err}
				s.markScannerRunning(ctx, jobID, name)
				s.markScannerFinished(ctx, jobID, name, nil, err)
				return
			}
			s.markScannerRunning(ctx, jobID, name)
			findings, err := s.executeScanner(ctx, jobID, name, scanner, target)
			packages := inventoryFor(ctx, scanner, target, &err)
			outcomes[i] = scannerOutcome{scanner: name, findings: findings, packages: packages, err: err}
			s.markScannerFinished(ctx, jobID, name, findings, err)
		}(i, name)
	}
	wg.Wait()
	return outcomes
}

// inventoryFor chama Inventory (Fase 11 — Syft) se, e só se, scanner
// também implementar domain.InventoryProvider (type assertion — o mesmo
// scanner pode participar do fluxo de achados, do de inventário, ou dos
// dois, ver docs/roadmap-secops-orchestrator.md). Pulado quando *err já
// aponta uma falha (ex.: Execute já falhou) — não faz sentido tentar
// inventariar um alvo que o próprio Execute não conseguiu processar. Um
// erro de Inventory sobrescreve *err: para um scanner cujo Execute é um
// no-op (Syft, que não produz achados), Inventory é a única chamada real
// que pode falhar de verdade, então o erro dela precisa ser o que o
// chamador (runConcurrently/RunScan) trata como a falha do scanner.
func inventoryFor(ctx context.Context, scanner domain.CodeScanner, target string, err *error) []domain.Package {
	if *err != nil {
		return nil
	}
	inv, ok := scanner.(domain.InventoryProvider)
	if !ok {
		return nil
	}
	packages, invErr := inv.Inventory(ctx, target)
	if invErr != nil {
		*err = invErr
		return nil
	}
	return packages
}

// runConcurrentlyLocal é o par de runConcurrently pro caso de um projeto
// criado por upload (Fase 10): em vez de scanner.Execute(ctx, target)
// (que clonaria um alvo git), chama scanner.(domain.LocalScanner).
// ExecuteLocal(ctx, dir) contra um diretório JÁ extraído — dir precisa
// vir de ZipExtractor.ExtractZip, chamado uma vez só por quem chama esta
// função (ProcessScanJob), não aqui: todo scanner deste job compartilha o
// MESMO diretório, então a extração acontece uma única vez pro job
// inteiro, nunca uma vez por scanner.
//
// Um scanner sem LocalScanner chegando aqui seria um bug de wiring —
// createScanJob já rejeita isso na CRIAÇÃO do job (ver "unsupported"
// acima) — mas o mesmo cenário defensivo de runConcurrently (scanner
// desregistrado entre a criação e o processamento) se aplica igual aqui,
// por isso a checagem continua, nunca um type assertion que entra em
// pânico.
func (s *Service) runConcurrentlyLocal(ctx context.Context, jobID uuid.UUID, scannerNames []string, dir string) []scannerOutcome {
	outcomes := make([]scannerOutcome, len(scannerNames))
	var wg sync.WaitGroup
	for i, name := range scannerNames {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			scanner, ok := s.scanners[name]
			if !ok {
				err := fmt.Errorf("scanner %q not registered", name)
				outcomes[i] = scannerOutcome{scanner: name, err: err}
				s.markScannerRunning(ctx, jobID, name)
				s.markScannerFinished(ctx, jobID, name, nil, err)
				return
			}
			s.markScannerRunning(ctx, jobID, name)
			local, ok := scanner.(domain.LocalScanner)
			if !ok {
				err := fmt.Errorf("scanner %q does not support scanning a local directory (upload-based project)", name)
				outcomes[i] = scannerOutcome{scanner: name, err: err}
				s.markScannerFinished(ctx, jobID, name, nil, err)
				return
			}
			findings, err := local.ExecuteLocal(ctx, dir)
			packages := inventoryForLocal(ctx, scanner, dir, &err)
			outcomes[i] = scannerOutcome{scanner: name, findings: findings, packages: packages, err: err}
			s.markScannerFinished(ctx, jobID, name, findings, err)
		}(i, name)
	}
	wg.Wait()
	return outcomes
}

// inventoryForLocal é o par local de inventoryFor — mesma lógica, só que
// via domain.LocalInventoryProvider.InventoryLocal em vez de
// InventoryProvider.Inventory.
func inventoryForLocal(ctx context.Context, scanner domain.CodeScanner, dir string, err *error) []domain.Package {
	if *err != nil {
		return nil
	}
	inv, ok := scanner.(domain.LocalInventoryProvider)
	if !ok {
		return nil
	}
	packages, invErr := inv.InventoryLocal(ctx, dir)
	if invErr != nil {
		*err = invErr
		return nil
	}
	return packages
}

// failAllScanners marca todo scanner de scannerNames como falho com o
// MESMO err — usado só quando algo impede QUALQUER scanner de sequer
// começar (Fase 10: falha ao extrair o .zip do projeto, ou o projeto
// sumiu entre a criação do job e o processamento) — sem isto, nenhuma
// linha apareceria em scanning_scanner_runs pra explicar por que o job
// falhou, e o painel de progresso ficaria vazio em vez de mostrar CADA
// scanner pedido com o motivo real.
func (s *Service) failAllScanners(ctx context.Context, jobID uuid.UUID, scannerNames []string, err error) []scannerOutcome {
	outcomes := make([]scannerOutcome, len(scannerNames))
	for i, name := range scannerNames {
		s.markScannerRunning(ctx, jobID, name)
		s.markScannerFinished(ctx, jobID, name, nil, err)
		outcomes[i] = scannerOutcome{scanner: name, err: err}
	}
	return outcomes
}

// markScannerRunning/markScannerFinished são escritas best-effort de
// progresso (ver domain.Repository.StartScannerRun/FinishScannerRun): uma
// falha aqui só vira um log — nunca derruba o scan em si, porque o
// progresso é observabilidade, não parte da garantia transacional de
// achados/eventos que persistCompletion tem.
func (s *Service) markScannerRunning(ctx context.Context, jobID uuid.UUID, name string) {
	if err := s.repo.StartScannerRun(ctx, jobID, name); err != nil {
		s.logger.Warn("scanning: failed to record scanner start (progress tracking only, scan continues)",
			slog.String("job_id", jobID.String()), slog.String("scanner", name), slog.Any("error", err))
	}
}

func (s *Service) markScannerFinished(ctx context.Context, jobID uuid.UUID, name string, findings []domain.Finding, err error) {
	status := domain.ScannerRunSucceeded
	errMsg := ""
	if err != nil {
		status = domain.ScannerRunFailed
		errMsg = err.Error()
	}
	if writeErr := s.repo.FinishScannerRun(ctx, jobID, name, status, len(findings), errMsg); writeErr != nil {
		s.logger.Warn("scanning: failed to record scanner finish (progress tracking only, scan continues)",
			slog.String("job_id", jobID.String()), slog.String("scanner", name), slog.Any("error", writeErr))
	}
}

// reportScannerProgress grava o sub-progresso de UM scanner ainda
// rodando (ver domain.ProgressReportingScanner) — mesma escrita
// best-effort de markScannerRunning/markScannerFinished, chamada
// potencialmente muitas vezes por scan (ZapScanner chama a cada 5s
// enquanto spider/scan ativo não terminam), então o log de falha aqui é
// Debug, não Warn: um Warn por tentativa acabaria inundando o log de um
// scan de 20 minutos sem trazer nada de novo depois da primeira falha.
func (s *Service) reportScannerProgress(ctx context.Context, jobID uuid.UUID, name, detail string) {
	if err := s.repo.UpdateScannerRunProgress(ctx, jobID, name, detail); err != nil {
		s.logger.Debug("scanning: failed to record scanner progress (progress tracking only, scan continues)",
			slog.String("job_id", jobID.String()), slog.String("scanner", name), slog.Any("error", err))
	}
}

// executeScanner chama Execute — ou, quando scanner também implementa
// domain.ProgressReportingScanner (hoje: só ZapScanner), ExecuteWithProgress
// com um reporter que grava em scanning_scanner_runs.progress_detail.
// Extraído de runConcurrently pra manter a checagem de sub-progresso num
// único lugar, nunca duplicada — runConcurrentlyLocal nunca chama isto:
// nenhum scanner que implementa LocalScanner (Trivy/Gitleaks/Semgrep/
// Syft) hoje também implementa ProgressReportingScanner, e ZAP nunca
// implementa LocalScanner (ataca uma URL viva, nunca um diretório).
func (s *Service) executeScanner(ctx context.Context, jobID uuid.UUID, name string, scanner domain.CodeScanner, target string) ([]domain.Finding, error) {
	reporting, ok := scanner.(domain.ProgressReportingScanner)
	if !ok {
		return scanner.Execute(ctx, target)
	}
	return reporting.ExecuteWithProgress(ctx, target, func(detail string) {
		s.reportScannerProgress(ctx, jobID, name, detail)
	})
}

func splitOutcomes(outcomes []scannerOutcome) (succeeded, failed []scannerOutcome) {
	for _, o := range outcomes {
		if o.err != nil {
			failed = append(failed, o)
		} else {
			succeeded = append(succeeded, o)
		}
	}
	return succeeded, failed
}

func outcomeNames(outcomes []scannerOutcome) []string {
	names := make([]string, len(outcomes))
	for i, o := range outcomes {
		names[i] = o.scanner
	}
	return names
}

func summarizeFailures(failed []scannerOutcome) string {
	parts := make([]string, len(failed))
	for i, o := range failed {
		parts[i] = fmt.Sprintf("%s: %v", o.scanner, o.err)
	}
	return strings.Join(parts, "; ")
}

// newScannerFailure extrai de scannerOutcome.err a mesma classificação de
// erro (Code) que a camada HTTP já usa pra decidir status code —
// reaproveitada aqui pra que quem consultar o resultado de um job (ver
// GetScanStatus) saiba o TIPO do erro sem fazer parsing de string livre.
// Um erro que não veio de apperrors não deveria acontecer nos
// CodeScanner de hoje (todos devolvem *apperrors.Error nas suas falhas
// conhecidas), mas defensivo contra um bug futuro que devolva um erro
// "cru" — cai em CodeInternal em vez de entrar em pânico ou perder a
// mensagem.
func newScannerFailure(o scannerOutcome) domain.ScannerFailure {
	if appErr, ok := apperrors.As(o.err); ok {
		return domain.ScannerFailure{Scanner: o.scanner, Code: string(appErr.Code), Message: appErr.Message}
	}
	return domain.ScannerFailure{Scanner: o.scanner, Code: string(apperrors.CodeInternal), Message: o.err.Error()}
}

func scannerFailures(outcomes []scannerOutcome) []domain.ScannerFailure {
	out := make([]domain.ScannerFailure, len(outcomes))
	for i, o := range outcomes {
		out[i] = newScannerFailure(o)
	}
	return out
}

// encodeFailures serializa as falhas de scanner de failed para o texto
// gravado em jobs.error (TEXT genérico, compartilhado com todo outro
// tipo de job desta plataforma) — JSON, não texto livre, pra que
// GetScanStatus consiga decodificar de volta em []domain.ScannerFailure
// sem parsing de string. summarizeFailures (texto livre, pensado pra
// leitura em log) continua existindo separadamente só pras mensagens de
// log desta package — os dois formatos servem públicos diferentes.
func encodeFailures(failed []scannerOutcome) string {
	data, err := json.Marshal(scannerFailures(failed))
	if err != nil {
		// Defensivo: json.Marshal de um []domain.ScannerFailure (só
		// campos string) não deveria falhar nunca — preferimos um
		// texto degradado, ainda útil em log, a perder jobs.error
		// inteiro por causa de um erro de serialização.
		return summarizeFailures(failed)
	}
	return string(data)
}

// ProcessScanJob implementa a execução do lado do worker (mesmo desenho
// de diario_oficial.Service.ProcessJob, incluindo a mesma idempotência
// contra redelivery do RabbitMQ: um job em estado terminal vira um no-op
// em vez de ser reprocessado). O scan_id usado em EventScanCompleted é o
// próprio jobID — não um uuid.New() separado — para que o cliente HTTP
// consiga consultar ListFindings com o mesmo ID recebido de
// CreateScanJob.
//
// Todo scanner do payload roda em paralelo (runConcurrently, Fase 7).
// Falha parcial (alguns scanners tiveram sucesso, outros não) marca o job
// como concluído, não como falho — reprocessar o job inteiro numa
// redelivery re-executaria também os scanners que JÁ tiveram sucesso,
// arriscando achados duplicados gravados sob o mesmo scan_id; o(s)
// scanner(s) que falhou(aram) fica(m) registrado(s) no resultado do job e
// nos metadados de auditoria, não silenciosamente perdido(s). Só quando
// TODOS os scanners falham o job inteiro é marcado como falho, pra ser
// reprocessado (mesma semântica de retry de antes desta fase).
func (s *Service) ProcessScanJob(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID) error {
	current, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("scanning: load job %s: %w", jobID, err)
	}
	if current.Status == jobs.StatusCompleted || current.Status == jobs.StatusDeadLetter {
		s.logger.Info("scanning: duplicate delivery of an already-finished job, skipping",
			slog.String("job_id", jobID.String()), slog.String("status", string(current.Status)))
		return nil
	}

	var payload scanJobPayload
	if err := json.Unmarshal(current.Payload, &payload); err != nil {
		return fmt.Errorf("scanning: decode job %s payload: %w", jobID, err)
	}

	// MarkProcessing sozinho, na SUA PRÓPRIA transação, ANTES de
	// runConcurrently — antes desta mudança, o job ficava "queued" (não
	// "processing") pelo tempo INTEIRO que os scanners rodavam, porque
	// MarkProcessing só era chamado dentro da mesma transação que
	// MarkCompleted/MarkFailed, DEPOIS de runConcurrently já ter
	// terminado. Um painel de progresso consultando GetScanStatus via
	// polling via via um job "queued" o tempo todo mesmo com scanners
	// visivelmente "running" em ScannerRuns — confuso pro pedido do
	// usuário de saber "qual teste está rodando". CanTransition permite
	// tanto queued->processing (primeira tentativa) quanto
	// failed->processing (retry depois de MarkFailed), então isto nunca
	// rejeita uma transição válida.
	if err := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		return s.jobsRepo.MarkProcessing(ctx, tx, jobID)
	}); err != nil {
		return fmt.Errorf("scanning: mark job %s processing: %w", jobID, err)
	}

	// Fase 10 — projeto criado por upload .zip: ProjectID preenchido (ver
	// scanJobPayload.ProjectID) faz este job re-buscar o domain.Project
	// pra saber o SourceType de verdade — um projeto GIT segue o caminho
	// de sempre abaixo (clona payload.Target normalmente, runConcurrently
	// sem nenhuma mudança de comportamento); um projeto UPLOAD não tem
	// alvo git nenhum pra clonar, então extrai o .zip do projeto pro
	// volume compartilhado e escaneia esse diretório (runConcurrentlyLocal)
	// em vez de clonar. payload.Target já vem certo dos dois jeitos desde
	// createScanJob/CreateProjectScanJob (o alvo git, ou o rótulo
	// sintético "upload:<projeto>" — ver uploadTarget) — persistCompletion
	// abaixo usa esse mesmo valor sempre, nunca recomputado aqui.
	var outcomes []scannerOutcome
	if payload.ProjectID != nil {
		project, err := s.repo.GetProject(ctx, *payload.ProjectID)
		if err != nil {
			outcomes = s.failAllScanners(ctx, jobID, payload.Scanners, fmt.Errorf("scanning: load project %s: %w", *payload.ProjectID, err))
		} else if project.SourceType == domain.ProjectSourceUpload {
			dir, cleanup, extractErr := s.zipExtractor.ExtractZip(project.UploadZip)
			if extractErr != nil {
				outcomes = s.failAllScanners(ctx, jobID, payload.Scanners, extractErr)
			} else {
				defer cleanup()
				outcomes = s.runConcurrentlyLocal(ctx, jobID, payload.Scanners, dir)
			}
		} else {
			outcomes = s.runConcurrently(ctx, jobID, payload.Scanners, payload.Target)
		}
	} else {
		outcomes = s.runConcurrently(ctx, jobID, payload.Scanners, payload.Target)
	}
	succeeded, failed := splitOutcomes(outcomes)

	txErr := database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if len(succeeded) == 0 {
			return s.jobsRepo.MarkFailed(ctx, tx, jobID, encodeFailures(failed))
		}
		return s.jobsRepo.MarkCompleted(ctx, tx, jobID, struct {
			SucceededScanners []string                `json:"succeeded_scanners"`
			FailedScanners    []domain.ScannerFailure `json:"failed_scanners,omitempty"`
		}{SucceededScanners: outcomeNames(succeeded), FailedScanners: scannerFailures(failed)})
	})
	if txErr != nil {
		return fmt.Errorf("scanning: record processing outcome: %w", txErr)
	}

	if len(succeeded) == 0 {
		s.logger.Warn("scanning: all scanners failed, will retry",
			slog.String("job_id", jobID.String()), slog.String("errors", summarizeFailures(failed)))
		return fmt.Errorf("scanning: all scanners failed: %s", summarizeFailures(failed))
	}

	if err := s.persistCompletion(ctx, jobID, payload.Target, correlationID, outcomes); err != nil {
		return err
	}

	if len(failed) > 0 {
		s.logger.Warn("scanning: job completed with partial failure",
			slog.String("job_id", jobID.String()), slog.Any("succeeded", outcomeNames(succeeded)),
			slog.String("failed", summarizeFailures(failed)))
	}

	if s.audit != nil {
		totalFindings := 0
		for _, o := range succeeded {
			totalFindings += len(o.findings)
		}
		_ = s.audit.Record(ctx, audit.Entry{
			Action:        audit.ActionScanCompleted,
			ResourceType:  "scan",
			ResourceID:    jobID.String(),
			CorrelationID: &correlationID,
			Metadata: map[string]any{
				"scanners":        outcomeNames(succeeded),
				"failed_scanners": outcomeNames(failed),
				"target":          payload.Target,
				"findings_count":  totalFindings,
			},
		})
	}
	return nil
}

// HandleScanDeadLetter é chamado quando o RabbitMQ já esgotou
// RABBITMQ_MAX_RETRIES para a mensagem deste job: o desfecho terminal, tal
// qual diario_oficial.Service.HandleDeadLetter — antes disso, toda falha
// era tratada como "ainda pode ter sucesso numa nova tentativa" (ver
// ProcessScanJob) e não publicava EventScanFailed.
//
// O motivo gravado como jobs.error não é mais um texto genérico fixo
// ("max retries exceeded"): isso descartava silenciosamente o motivo de
// verdade (qual scanner falhou, com que tipo de erro e mensagem) que
// ProcessScanJob já tinha gravado na ÚLTIMA tentativa via MarkFailed —
// bug real, encontrado enquanto o usuário investigava por que um disparo
// de scan "deu errado" e só via "max retries exceeded" no resultado
// final, sem nenhuma pista do motivo. Em vez de sobrescrever, carrega o
// job atual e reaproveita seu jobs.error (já no formato JSON de
// []domain.ScannerFailure produzido por encodeFailures) verbatim — só
// cai no texto genérico se, por algum motivo defensivo (job nunca passou
// por MarkFailed antes de ser dado como esgotado), não houver nada
// gravado ainda.
func (s *Service) HandleScanDeadLetter(ctx context.Context, jobID uuid.UUID, correlationID uuid.UUID) error {
	current, err := s.jobsRepo.GetByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("scanning: load job %s for dead letter: %w", jobID, err)
	}
	reason := "max retries exceeded"
	if current.Error != nil && *current.Error != "" {
		reason = *current.Error
	}

	err = database.WithTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.jobsRepo.MarkDeadLetter(ctx, tx, jobID, reason); err != nil {
			return err
		}
		return s.outboxWriter.Write(ctx, tx, EventScanFailed, "job", jobID.String(), correlationID, jobRefPayload{JobID: jobID})
	})
	if err != nil {
		return fmt.Errorf("scanning: handle dead letter: %w", err)
	}

	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			Action:        audit.ActionScanFailed,
			ResourceType:  "job",
			ResourceID:    jobID.String(),
			CorrelationID: &correlationID,
			Metadata:      map[string]any{"reason": reason},
		})
	}
	return nil
}
