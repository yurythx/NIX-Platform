// Arquivo csv_export.go (Fase 14 — Maturidade de AppSec,
// docs/roadmap-secops-orchestrator.md): o primeiro formato de exportação
// desta plataforma. Até aqui, tirar um achado da NIX Platform significava
// copiar da tela na mão ou consumir a API JSON — sem nada que uma
// auditoria de segurança, uma planilha de acompanhamento ou um board de
// Jira importasse direto. CSV é o menor denominador comum: toda
// ferramenta de planilha/BI abre sem parser nenhum. SARIF (o formato que
// GitHub Code Scanning consome nativamente) fica documentado como
// próximo passo natural, não implementado agora — ver "Fora de escopo"
// no roadmap: um exportador SARIF correto precisa modelar `rules`/
// `results`/`physicalLocation` por scanner de origem, escopo maior que
// zero risco de sair com um arquivo tecnicamente inválido sem uma
// ferramenta de validação contra o schema à mão neste ambiente.
package transport

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

// writeCSVHeaders escreve os headers HTTP de download (Content-Type +
// Content-Disposition attachment, pra um clique no link do frontend virar
// um download de arquivo em vez de abrir CSV cru na aba) e devolve um
// csv.Writer já pronto pra escrever linhas em w.
func writeCSVHeaders(w http.ResponseWriter, filename string) *csv.Writer {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	return csv.NewWriter(w)
}

// csvTimeLayout: RFC 3339 — o mesmo formato que toda resposta JSON desta
// API já usa pra time.Time (encoding/json's default), só que escrito na
// mão aqui porque encoding/csv não serializa time.Time sozinho.
const csvTimeLayout = "2006-01-02T15:04:05Z07:00"

// ExportFindings trata GET /api/v1/scanning/scans/{scanID}/findings.csv —
// o equivalente em CSV de ListFindings (mesmo achado, mesmo filtro de
// ruído se a flag estiver ligada — ListFindings já aplica isso, este
// handler não duplica a regra). Uma linha por achado, sem deduplicação
// (isto é UM scan; achado repetido entre re-scans é o que
// ExportProjectFindingsHistory resolve).
func (h *Handlers) ExportFindings(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "scanID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("scanID must be a valid UUID"))
		return
	}

	findings, err := h.service.ListFindings(r.Context(), scanID)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	cw := writeCSVHeaders(w, fmt.Sprintf("nix-scan-%s-findings.csv", scanID))
	_ = cw.Write([]string{"severity", "scanner", "finding_id", "owasp_category", "file", "line", "description", "target", "created_at"})
	for _, f := range findings {
		_ = cw.Write([]string{
			string(f.Severity), f.Scanner, f.Finding.ID, f.OWASPCategory,
			f.File, strconv.Itoa(f.Line), f.Description, f.Target, f.CreatedAt.Format(csvTimeLayout),
		})
	}
	cw.Flush()
}

// ExportProjectFindingsHistory trata GET
// /api/v1/scanning/projects/{projectID}/findings-history.csv — o
// equivalente em CSV de ListProjectFindingsHistory: uma linha por
// FINGERPRINT (deduplicado entre todo re-scan do projeto), com a
// triagem (Fase 14) incluída — a exportação que faz sentido levar pra
// uma reunião de status ou um ticket de compliance, ao contrário de
// ExportFindings (uma execução isolada).
func (h *Handlers) ExportProjectFindingsHistory(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("projectID must be a valid UUID"))
		return
	}

	history, err := h.service.ListProjectFindingsHistory(r.Context(), projectID)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	cw := writeCSVHeaders(w, fmt.Sprintf("nix-project-%s-findings-history.csv", projectID))
	_ = cw.Write([]string{
		"severity", "scanner", "owasp_category", "file", "line", "description",
		"first_seen_at", "last_seen_at", "scan_count", "still_present", "triage_status", "triage_reason",
	})
	for _, hist := range history {
		_ = cw.Write([]string{
			string(hist.Severity), hist.Scanner, hist.OWASPCategory, hist.File, strconv.Itoa(hist.Line), hist.Description,
			hist.FirstSeenAt.Format(csvTimeLayout), hist.LastSeenAt.Format(csvTimeLayout),
			strconv.Itoa(hist.ScanCount), strconv.FormatBool(hist.StillPresent), hist.TriageStatus, hist.TriageReason,
		})
	}
	cw.Flush()
}
