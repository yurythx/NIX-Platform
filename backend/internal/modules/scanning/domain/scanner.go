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
	CreatedAt time.Time
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
}
