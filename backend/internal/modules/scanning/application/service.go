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
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/audit"
	"github.com/yurythx/nix-platform/internal/platform/configflags"
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
