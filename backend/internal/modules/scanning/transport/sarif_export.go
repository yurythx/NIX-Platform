// Arquivo sarif_export.go — SARIF (Static Analysis Results Interchange
// Format) 2.1.0, o formato que GitHub Code Scanning (e Azure DevOps, e a
// maioria das ferramentas de CI de segurança) consome nativamente: um
// upload de SARIF vira anotação direto no diff do PR e na aba Security,
// sem esta plataforma precisar construir nenhuma UI de comentário em PR
// própria (ver docs/roadmap-secops-orchestrator.md, "Reestruturação de
// /seguranca" e adiante — CSV (csv_export.go) já cobria planilha/
// auditoria; SARIF é o formato que faltava pra "shift-left" de verdade).
//
// Só o subconjunto de campos do schema oficial que este exportador de
// fato preenche está modelado aqui (não o spec inteiro) — cada struct
// carrega um comentário citando o `required` do schema oficial
// (raw.githubusercontent.com/schemastore/schemastore, sarif-2.1.0.json)
// que ela precisa satisfazer. O JSON gerado foi validado com ajv-cli
// (draft-07, o mesmo draft que o $schema do SARIF 2.1.0 declara) contra
// o schema oficial antes deste arquivo ser commitado — não é só "parece
// certo", foi checado contra o schema de verdade.
package transport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"

// sarifLog é a raiz do documento — required: ["version", "runs"]
// (definitions.sarifLog no schema oficial).
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun — required: ["tool"]. Um run por SCANNER, não por scan: o
// modelo do SARIF é "uma ferramenta de análise produziu este conjunto de
// resultados", e um scan da NIX tipicamente roda várias ferramentas
// (trivy, gitleaks, ...) juntas.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool — required: ["driver"].
type sarifTool struct {
	Driver sarifToolComponent `json:"driver"`
}

// sarifToolComponent (o "driver") — required: ["name"].
type sarifToolComponent struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules,omitempty"`
}

// sarifRule (reportingDescriptor) — required: ["id"]. Uma por Finding.ID
// DISTINTO dentro do run (ex.: "CVE-2026-12345" aparece uma vez em
// `rules`, mesmo que o mesmo CVE apareça em 3 `results` diferentes —
// arquivos/linhas diferentes).
type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	FullDescription  *sarifMessage     `json:"fullDescription,omitempty"`
	Properties       *sarifPropertyBag `json:"properties,omitempty"`
}

// sarifPropertyBag — additionalProperties: true no schema oficial, então
// "security-severity" (a convenção do GitHub Code Scanning pra colorir a
// severidade na UI, um score 0.0–10.0 em texto) é uma extensão válida,
// não um campo inventado fora do schema.
type sarifPropertyBag struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

// sarifResult — required: ["message"]. RuleID/Level não são obrigatórios
// pelo schema, mas sem eles o GitHub Code Scanning não sabe agrupar nem
// colorir o resultado — sempre preenchidos aqui.
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

// sarifMessage — required: ["text"] (na prática; o schema não marca
// nenhum campo de `message` como obrigatório, mas um message sem texto
// não serve pra nada).
type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifRegion — startLine tem `"minimum": 1` no schema oficial: por isso
// nunca é preenchido pra um Finding com Line == 0 (achado sem arquivo
// específico, ex.: DAST) — omitir o Region inteiro, nunca mandar 0.
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// severityToSarifLevel traduz a escala própria desta plataforma pro
// enum fechado do SARIF (["none","note","warning","error"] — ver
// definitions.result.properties.level no schema oficial). CRITICAL/HIGH
// viram "error" (o único nível que barra um gate de CI por padrão no
// GitHub Code Scanning); MEDIUM vira "warning"; LOW vira "note".
func severityToSarifLevel(sev domain.Severity) string {
	switch sev {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	case domain.SeverityLow:
		return "note"
	default:
		return "warning"
	}
}

// severityToSecurityScore é a convenção do GitHub Code Scanning pra
// `properties["security-severity"]` na regra — um score CVSS-like em
// string, não o enum de `level` (que é sobre o RESULTADO, não a regra).
// Sem isso, todo achado aparece com a mesma cor neutra na aba Security do
// GitHub, sem distinguir crítico de baixo visualmente.
func severityToSecurityScore(sev domain.Severity) string {
	switch sev {
	case domain.SeverityCritical:
		return "9.5"
	case domain.SeverityHigh:
		return "7.5"
	case domain.SeverityMedium:
		return "4.5"
	case domain.SeverityLow:
		return "1.5"
	default:
		return "0.0"
	}
}

// shortDescriptionText — shortDescription é documentado no schema oficial
// como "should be a single sentence... visible when limited to a single
// line of text": trunca uma Description longa em vez de estourar isso,
// sem perder a informação (fullDescription carrega o texto inteiro).
func shortDescriptionText(description string) string {
	const maxLen = 120
	if len(description) <= maxLen {
		return description
	}
	return strings.TrimSpace(description[:maxLen]) + "…"
}

// buildSarifLog agrupa achados por Scanner (um run por ferramenta) e
// dentro de cada run agrupa por Finding.ID (uma rule por ID distinto,
// vários results podem apontar pra mesma rule). scanners é a lista de
// ferramentas que RODARAM com sucesso neste scan (ScanStatus.
// SucceededScanners) — garante um run (com 0 results) pra toda ferramenta
// que rodou e não achou nada, não só pras que acharam algo: um consumidor
// de SARIF (GitHub incluso) usa a AUSÊNCIA de um run pra inferir "essa
// ferramenta nunca rodou", o que seria enganoso pra um scanner limpo.
func buildSarifLog(scanners []string, findings []domain.PersistedFinding) sarifLog {
	byScanner := make(map[string][]domain.PersistedFinding, len(scanners))
	for _, name := range scanners {
		byScanner[name] = nil
	}
	for _, f := range findings {
		byScanner[f.Scanner] = append(byScanner[f.Scanner], f)
	}

	names := make([]string, 0, len(byScanner))
	for name := range byScanner {
		names = append(names, name)
	}
	sort.Strings(names)

	runs := make([]sarifRun, 0, len(names))
	for _, name := range names {
		runs = append(runs, buildSarifRun(name, byScanner[name]))
	}

	return sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs:    runs,
	}
}

func buildSarifRun(scannerName string, findings []domain.PersistedFinding) sarifRun {
	rulesByID := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		if _, exists := rulesByID[f.ID]; !exists {
			rule := sarifRule{
				ID:               f.ID,
				ShortDescription: sarifMessage{Text: shortDescriptionText(f.Description)},
				Properties: &sarifPropertyBag{
					SecuritySeverity: severityToSecurityScore(f.Severity),
				},
			}
			if f.Description != "" {
				rule.FullDescription = &sarifMessage{Text: f.Description}
			}
			if f.OWASPCategory != "" {
				rule.Properties.Tags = []string{"security", f.OWASPCategory}
			} else {
				rule.Properties.Tags = []string{"security"}
			}
			rulesByID[f.ID] = rule
		}

		result := sarifResult{
			RuleID:  f.ID,
			Level:   severityToSarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Description},
		}
		if f.File != "" {
			loc := sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: f.File}}
			if f.Line > 0 {
				loc.Region = &sarifRegion{StartLine: f.Line}
			}
			result.Locations = []sarifLocation{{PhysicalLocation: loc}}
		}
		results = append(results, result)
	}

	ruleIDs := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, rulesByID[id])
	}

	return sarifRun{
		Tool: sarifTool{
			Driver: sarifToolComponent{
				Name:  scannerName,
				Rules: rules,
			},
		},
		Results: results,
	}
}

// ExportFindingsSarif trata GET /api/v1/scanning/scans/{scanID}/findings.sarif
// — o equivalente SARIF de ExportFindings (csv_export.go). Mesma
// permissão/mesmo escopo (um scan, não deduplicado entre re-scans: SARIF
// representa UMA execução de análise, igual ExportFindings em CSV).
func (h *Handlers) ExportFindingsSarif(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "scanID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("scanID must be a valid UUID"))
		return
	}

	status, err := h.service.GetScanStatus(r.Context(), scanID)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	findings, err := h.service.ListFindings(r.Context(), scanID)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	log := buildSarifLog(status.SucceededScanners, findings)

	// Escreve o documento SARIF cru na raiz da resposta — nunca dentro do
	// envelope {data, error, meta} padrão desta API (httputil.WriteJSON):
	// um consumidor de SARIF (GitHub Code Scanning, `sarif-cli`, um `next
	// upload-sarif` de CI) espera {"version": ..., "runs": [...]} direto
	// na raiz do arquivo, o schema oficial não conhece nem toleraria um
	// envelope por cima.
	w.Header().Set("Content-Type", "application/sarif+json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="nix-scan-%s-findings.sarif"`, scanID))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(log)
}
