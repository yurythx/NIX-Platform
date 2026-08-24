// Package domain guarda a entidade e os contratos do módulo scanning —
// Fase 1 do roadmap de segurança (docs/roadmap-secops-orchestrator.md)
// definiu o modelo e o Service; a Fase Trivy adicionou o primeiro
// CodeScanner real (scanning/infrastructure.TrivyScanner). O Service
// continua testado inteiramente contra um scanner falso
// (ver application/service_test.go) — nenhum teste depende do binário
// trivy estar instalado.
package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Severity é a gravidade de um achado, seguindo a mesma escala que
// scanners de segurança do mercado (Trivy, Semgrep, Grype, ...) já usam —
// não uma escala própria que cada adaptador precisaria traduzir.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Finding é o modelo unificado de achado — todo CodeScanner devolve uma
// lista destes, não importa se a ferramenta por trás fala JSON, XML ou
// SARIF nativamente (essa tradução é responsabilidade do Adapter, ou
// seja, da implementação concreta de CodeScanner — nunca deste pacote).
type Finding struct {
	// ID identifica o achado especificamente — um CVE (ex.:
	// "CVE-2026-12345") para achados de dependência/container, ou uma
	// regra própria da ferramenta (ex.:
	// "semgrep:go.lang.security.audit.sql-injection") para SAST.
	ID string
	// OWASPCategory associa o achado a uma categoria do Top 10 (ex.:
	// "A03:2021-Injection") quando o scanner consegue inferir isso —
	// vazio quando não se aplica ou a ferramenta não classifica dessa
	// forma.
	OWASPCategory string
	Severity      Severity
	Description   string
	// File e Line ficam vazios/zero para achados que não são de um
	// arquivo específico (ex.: um achado de DAST contra uma API rodando).
	File string
	Line int
	// Snippet é um trecho do código-fonte ao redor de Line (Fase 12) —
	// capturado NO MOMENTO do scan, enquanto o clone/checkout temporário
	// ainda existe (nunca lido depois sob demanda: a plataforma não
	// mantém checkout persistido nenhum, ver docs/roadmap-secops-
	// orchestrator.md, "Reconciliação"). Vazio quando não há arquivo
	// (mesmo caso de File vazio) ou quando o scanner não captura
	// snippet.
	Snippet string
}

// Fingerprint identifica o "mesmo" achado entre execuções — SHA-256 de
// scanner+findingID+file+line, curto o bastante pra comparar/indexar,
// determinístico o bastante pra um re-scan do mesmo projeto (Fase 10)
// reconhecer "isto já apareceu antes" sem depender de nenhum ID que a
// ferramenta de origem tenha gerado (nem toda ferramenta garante um ID
// estável entre execuções, mas scanner+regra/CVE+arquivo+linha já
// identifica o achado o bastante pra este propósito).
func Fingerprint(scanner, findingID, file string, line int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", scanner, findingID, file, line)))
	return hex.EncodeToString(sum[:])
}

// CodeScanner é o contrato que toda ferramenta de scanning implementa
// (Strategy Pattern) — desenhado para devolver uma LISTA de achados, ao
// contrário de um provedor de resultado único (ex.: um lookup externo
// "essa entidade é maliciosa? sim/não"), porque é isso que scanners de
// código/dependência/DAST de verdade produzem: um scan pode encontrar
// dezenas de achados discretos numa única execução.
type CodeScanner interface {
	Name() string
	Execute(ctx context.Context, target string) ([]Finding, error)
}

// PersistedFinding é um Finding já gravado, com os metadados que só
// existem depois da persistência (ID próprio da linha, a que scan
// pertence, quando foi gravado) — o que ListByScanID devolve. Finding em
// si (o que um CodeScanner produz) nunca carrega isso, para não obrigar
// toda implementação de CodeScanner a inventar um ID/timestamp que ainda
// não existem no momento em que o achado é só um resultado de execução.
//
// O campo da linha se chama RecordID, não ID: Finding já tem seu próprio
// ID (o CVE/regra do achado) — se os dois se chamassem ID, o embedding
// faria o de PersistedFinding esconder o de Finding tanto no acesso Go
// quanto na serialização JSON (a mesma regra de shadowing golpeia os
// dois), apagando silenciosamente o CVE/regra de toda resposta HTTP.
type PersistedFinding struct {
	RecordID uuid.UUID
	ScanID   uuid.UUID
	Scanner  string
	Target   string
	Finding
	// FindingFingerprint (não "Fingerprint": colidiria por shadowing com
	// um futuro campo de mesmo nome em Finding, mesmo raciocínio do
	// RecordID/ID acima) — calculado por Fingerprint() no momento de
	// gravar (ver infrastructure.PostgresRepository.SaveFindings), nunca
	// pelo próprio CodeScanner.
	FindingFingerprint string
	CreatedAt          time.Time
}

// ScannerFailure descreve a falha de UM scanner dentro da execução de um
// job (ProcessScanJob) — Scanner identifica QUAL ferramenta falhou, Code é
// a mesma taxonomia de internal/domain/errors.Code (ex.:
// "DEPENDENCY_UNAVAILABLE", "VALIDATION_ERROR") pra classificar o TIPO de
// erro sem que quem exibe isso precise fazer parsing de string livre, e
// Message é a descrição legível já produzida pelo scanner/adapter (ex.:
// "scanning: git clone failed: fatal: ..."). Usado tanto no resultado de
// um job parcialmente concluído (alguns scanners falharam, outros não,
// ver application.Service.ProcessScanJob) quanto no motivo registrado de
// um job totalmente falho/dead-letter — a mesma estrutura nos dois
// lugares, pra GetScanStatus nunca precisar de dois formatos diferentes
// dependendo do status do job.
type ScannerFailure struct {
	Scanner string `json:"scanner"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ScannerRunStatus é o estado de UM scanner dentro da execução de um job
// — "running" enquanto scanner.Execute ainda não retornou,
// "succeeded"/"failed" quando termina. Existe pra dar visibilidade de
// progresso EM TEMPO REAL de um job ainda "processing": jobs.Status
// sozinho não distingue "acabei de começar" de "só falta um scanner
// terminar" — pedido do usuário foi exatamente um painel mostrando qual
// scanner está rodando agora e quanto falta.
type ScannerRunStatus string

const (
	ScannerRunRunning   ScannerRunStatus = "running"
	ScannerRunSucceeded ScannerRunStatus = "succeeded"
	ScannerRunFailed    ScannerRunStatus = "failed"
)

// ScannerRun é o progresso de UM scanner dentro de um job — ver
// Repository.ListScannerRuns. FindingsCount só é preenchido quando
// Status == ScannerRunSucceeded (nil enquanto ainda "running", ou se
// falhou — não haveria uma contagem de achados significativa nesses
// casos). FinishedAt é nil enquanto Status == ScannerRunRunning.
type ScannerRun struct {
	Scanner       string
	Status        ScannerRunStatus
	StartedAt     time.Time
	FinishedAt    *time.Time
	FindingsCount *int
	Error         string
}

// Repository persiste e consulta os achados de uma execução de scan.
type Repository interface {
	// SaveFindings grava todo achado de scanID numa única operação,
	// dentro da transação de quem chama (ver
	// application.Service.RunScan) — atômico com o evento de outbox
	// gravado na mesma transação, para nunca existir um achado
	// persistido sem o evento correspondente publicado, ou vice-versa.
	SaveFindings(ctx context.Context, tx pgx.Tx, scanID uuid.UUID, scanner, target string, findings []Finding) error

	// ListByScanID retorna todo achado de uma execução, mais recente
	// primeiro. Uma lista vazia (scan limpo, ou scanID desconhecido) não
	// é erro — quem chama decide se isso merece um 404.
	ListByScanID(ctx context.Context, scanID uuid.UUID) ([]PersistedFinding, error)

	// ListRecent retorna os achados mais graves/recentes entre TODAS as
	// execuções de scan (não só uma), até limit linhas — o feed que a
	// Fase 9 (UI no frontend) usa pra listar "achados recentes por
	// severidade" sem que quem chama precise já saber um scan_id de
	// antemão (ListByScanID sozinho não serve pra isso).
	ListRecent(ctx context.Context, limit int) ([]PersistedFinding, error)

	// StartScannerRun registra que scanner começou a rodar dentro de
	// jobID — chamado no INÍCIO de cada goroutine de
	// application.Service.runConcurrently, antes de scanner.Execute, pra
	// o progresso aparecer assim que o scanner começa, não só quando
	// termina. Uma redelivery do mesmo job (depois de MarkFailed)
	// reaproveita a mesma linha (job_id, scanner) — upsert, não insert —
	// pra sempre refletir a tentativa mais recente, nunca acumular
	// histórico de tentativas antigas.
	//
	// Escrita best-effort do ponto de vista de quem chama: uma falha
	// aqui nunca derruba o scan em si (ver Service.markScannerRunning) —
	// isto é só observabilidade, não faz parte da garantia transacional
	// de achados/eventos que SaveFindings tem.
	StartScannerRun(ctx context.Context, jobID uuid.UUID, scanner string) error

	// FinishScannerRun registra o desfecho de UM scanner — status,
	// contagem de achados (só relevante/gravada se status ==
	// ScannerRunSucceeded) e a mensagem de erro (só relevante se status
	// == ScannerRunFailed). Mesma escrita best-effort de
	// StartScannerRun.
	FinishScannerRun(ctx context.Context, jobID uuid.UUID, scanner string, status ScannerRunStatus, findingsCount int, errMsg string) error

	// ListScannerRuns retorna o progresso de todo scanner de jobID, na
	// ordem em que começaram a rodar — funciona pra um job em QUALQUER
	// status, inclusive "processing" (é exatamente esse caso, um job
	// ainda em andamento, que dá visibilidade real de progresso). Uma
	// lista vazia (job ainda não chegou a rodar nenhum scanner, ou jobID
	// desconhecido) não é erro.
	ListScannerRuns(ctx context.Context, jobID uuid.UUID) ([]ScannerRun, error)

	// CreateProject grava um Project novo (Fase 10) — p.ID é preenchido
	// por quem chama antes (uuid.New(), mesmo padrão de jobs.New), não
	// gerado aqui.
	CreateProject(ctx context.Context, p Project) error

	// GetProject busca um projeto por ID — ErrProjectNotFound (via
	// apperrors.NotFound na camada application) se não existir.
	GetProject(ctx context.Context, id uuid.UUID) (Project, error)

	// ListProjects retorna os projetos mais recentes primeiro, até
	// limit.
	ListProjects(ctx context.Context, limit int) ([]Project, error)

	// SavePackages grava o inventário (Fase 11 — Syft) de uma execução
	// de scan, mesma atomicidade de SaveFindings (dentro da transação de
	// quem chama). Uma lista vazia não é erro.
	SavePackages(ctx context.Context, tx pgx.Tx, scanID uuid.UUID, packages []Package) error

	// ListPackagesByScanID retorna o inventário de uma execução —
	// equivalente de ListByScanID, mas pra pacotes, não achados.
	ListPackagesByScanID(ctx context.Context, scanID uuid.UUID) ([]Package, error)
}

// Project (Fase 10) é o registro leve de um alvo recorrente — nome, de
// onde vem (git ou upload) — NUNCA o checkout em si (decisão explícita
// do usuário, ver "Reconciliação" em docs/roadmap-secops-orchestrator.md:
// o worker escala horizontalmente via RabbitMQ, persistir um checkout
// por projeto reintroduziria estado por réplica). Um projeto git guarda
// só a URL (re-clonada a cada scan); um projeto de upload guarda os
// BYTES do .zip enviado (bounded pelo tamanho do upload em si, extraído
// de novo a cada re-scan, nunca mantido descompactado entre execuções).
type ProjectSourceType string

const (
	ProjectSourceGit    ProjectSourceType = "git"
	ProjectSourceUpload ProjectSourceType = "upload"
)

type Project struct {
	ID         uuid.UUID
	Name       string
	SourceType ProjectSourceType
	Target     string // URL git — vazio quando SourceType == ProjectSourceUpload
	// UploadZip só é lido/gravado quando SourceType == ProjectSourceUpload
	// — nil (não um slice vazio) representa "sem upload", pra nunca
	// confundir com um .zip de verdade vazio de conteúdo.
	UploadZip []byte
	CreatedAt time.Time
}

// Package (Fase 11 — Syft) é UM item do inventário de dependências de
// uma execução de scan — estruturalmente diferente de Finding: um
// pacote não é "um erro pra corrigir", é só um fato ("esta versão desta
// biblioteca está presente"). Por isso nunca reaproveita Finding, e
// InventoryProvider é uma interface separada de CodeScanner — nem todo
// scanner produz um inventário (hoje só Syft).
type Package struct {
	Name    string
	Version string
	Type    string // ex.: "go-module", "npm", "python"
	License string
}

// InventoryProvider é implementado só por scanners que produzem
// inventário, não achados de segurança — hoje só Syft. Um type assertion
// (scanner.(InventoryProvider)) no Service decide se um scanner
// registrado participa do fluxo de achados, do de inventário, ou dos
// dois, sem inflar CodeScanner com um método que a maioria dos scanners
// não teria como implementar de verdade.
type InventoryProvider interface {
	Inventory(ctx context.Context, target string) ([]Package, error)
}

// LocalScanner (Fase 8 — cmd/secscan; Fase 10 — projeto criado por upload
// .zip) é implementado por um CodeScanner que também sabe escanear um
// diretório JÁ presente em disco, sem clonar nada — hoje: Trivy, Semgrep,
// Gitleaks. Não é implementado por SonarQube (precisa de um `git clone`
// pra derivar a project key que o servidor exige) nem por ZAP (ataca uma
// URL viva, nunca um diretório) — um scan de projeto por upload que pede
// um desses dois é rejeitado na criação do job (ver
// application.Service.CreateScanJob), nunca silenciosamente ignorado. Um
// type assertion (scanner.(LocalScanner)) decide por scanner, mesmo
// padrão de InventoryProvider acima.
type LocalScanner interface {
	ExecuteLocal(ctx context.Context, dir string) ([]Finding, error)
}

// LocalInventoryProvider é o par local de InventoryProvider — hoje só
// Syft. Existe pra que um projeto criado por upload também ganhe um
// inventário (Fase 11), não só achados.
type LocalInventoryProvider interface {
	InventoryLocal(ctx context.Context, dir string) ([]Package, error)
}

// ZipExtractor extrai os bytes de um .zip (Fase 10 — Project.UploadZip)
// pra um diretório novo dentro do volume compartilhado — o par de
// cloneShallow (git_clone.go) pro caso de upload em vez de git. Fica como
// uma interface aqui (não uma função livre em infrastructure chamada
// direto) pra que application.Service dependa só de domain, nunca de
// infrastructure — mesma Inversão de Dependência que já vale pro resto
// desta camada (Repository, CodeScanner, ...). Implementado em
// infrastructure/zip_extract.go.
type ZipExtractor interface {
	ExtractZip(zipBytes []byte) (dir string, cleanup func(), err error)
}
