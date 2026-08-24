package transport

import (
	"strings"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/application"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// FindingResponse é o formato público de um achado persistido — mesmo
// padrão de integrations/transport/dto.go: o domain.PersistedFinding
// nunca é serializado direto (seus campos não têm tag json, então
// sairiam em PascalCase, inconsistente com o resto da API, que é sempre
// snake_case).
type FindingResponse struct {
	ID            string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	Scanner       string    `json:"scanner"`
	Target        string    `json:"target"`
	FindingID     string    `json:"finding_id"`
	OWASPCategory string    `json:"owasp_category"`
	Severity      string    `json:"severity"`
	Description   string    `json:"description"`
	File          string    `json:"file"`
	Line          int       `json:"line"`
	CreatedAt     time.Time `json:"created_at"`
}

func toFindingResponse(f domain.PersistedFinding) FindingResponse {
	return FindingResponse{
		ID:            f.RecordID.String(),
		ScanID:        f.ScanID.String(),
		Scanner:       f.Scanner,
		Target:        f.Target,
		FindingID:     f.Finding.ID,
		OWASPCategory: f.OWASPCategory,
		Severity:      string(f.Severity),
		Description:   f.Description,
		File:          f.File,
		Line:          f.Line,
		CreatedAt:     f.CreatedAt,
	}
}

func toFindingResponses(list []domain.PersistedFinding) []FindingResponse {
	out := make([]FindingResponse, 0, len(list))
	for _, f := range list {
		out = append(out, toFindingResponse(f))
	}
	return out
}

// ScannerFailureResponse é o formato público de domain.ScannerFailure,
// com Hint computado aqui (camada de apresentação) — o texto de "como
// corrigir" nunca fica persistido, só é derivado de Code/Message/Scanner
// na hora de montar a resposta HTTP (ver remediationHint), pra poder
// melhorar a sugestão sem precisar reprocessar nenhum job antigo.
type ScannerFailureResponse struct {
	Scanner string `json:"scanner"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

func toScannerFailureResponses(list []domain.ScannerFailure) []ScannerFailureResponse {
	out := make([]ScannerFailureResponse, 0, len(list))
	for _, f := range list {
		out = append(out, ScannerFailureResponse{
			Scanner: f.Scanner,
			Code:    f.Code,
			Message: f.Message,
			Hint:    remediationHint(f),
		})
	}
	return out
}

// remediationHint traduz uma falha de scanner numa sugestão de correção
// acionável — o "como corrigir" que o usuário pediu explicitamente, ao
// lado de "qual ferramenta achou o erro" (Scanner) e "que tipo de erro"
// (Code), que domain.ScannerFailure já carrega sem precisar de nenhum
// texto adicional aqui. Verifica primeiro por trechos conhecidos da
// MENSAGEM — as causas mais comuns já vistas em produção neste ambiente
// (git clone falhando contra repositório privado/inexistente, ZAP sem
// nenhum host na allowlist) — caindo pra uma sugestão só pelo Code
// quando a mensagem não bate com nenhum desses casos conhecidos: nunca
// fica sem hint nenhum, mesmo para um erro nunca visto antes.
func remediationHint(f domain.ScannerFailure) string {
	msg := strings.ToLower(f.Message)

	switch {
	case strings.Contains(msg, "could not read username") || strings.Contains(msg, "authentication failed") || strings.Contains(msg, "permission denied"):
		return "O repositório parece exigir autenticação (privado, ou credencial expirada/errada). Use um repositório público, ou configure acesso autenticado antes de disparar o scan — hoje o worker só clona via HTTPS anônimo."
	case strings.Contains(msg, "repository") && strings.Contains(msg, "not found"):
		return "O repositório informado não existe, ou a URL está errada. Confira o endereço https:// e, se usou um branch/tag depois de \"#\", confirme que ele existe."
	case strings.Contains(msg, "no hosts are allowlisted") || strings.Contains(msg, "allowlist"):
		return "O ZAP só ataca hosts explicitamente autorizados. Adicione o host à variável de ambiente SCANNING_ZAP_ALLOWED_HOSTS do backend-worker e dispare o scan de novo."
	case strings.Contains(msg, "resolves to a private/internal address") || strings.Contains(msg, "private/internal"):
		return "O host do alvo resolve para um endereço privado/interno — bloqueado por proteção contra SSRF. Use um alvo público, alcançável pela internet."
	case strings.Contains(msg, "git clone failed"):
		return "Falha ao clonar o alvo via git. Confira se a URL é https://, se o repositório é público, e se o branch/tag depois de \"#\" (se algum foi passado) existe."
	case strings.Contains(msg, "target must be an https") || strings.Contains(msg, "not a valid branch/tag"):
		return "O alvo enviado não está no formato esperado. Para Trivy/Semgrep/SonarQube, uma URL https:// de um repositório git (opcionalmente com #branch); para o ZAP, a URL http(s) de um serviço já rodando."
	}

	switch f.Code {
	case string(apperrors.CodeValidation):
		return "O alvo enviado não passou na validação. Confira o formato (URL https:// para Trivy/Semgrep/SonarQube, URL http(s) de um serviço rodando para o ZAP)."
	case string(apperrors.CodeDependencyUnavailable):
		return "A ferramenta, ou uma dependência dela (git, o binário do scanner, a API do SonarQube/ZAP), não respondeu como esperado. Veja a mensagem acima para o motivo específico; se persistir, verifique se o serviço está no ar."
	case string(apperrors.CodeNotFound):
		return "O scanner pedido não está registrado neste ambiente — confira o nome (trivy, semgrep, sonarqube, zap)."
	default:
		return "Erro inesperado nesta ferramenta. Consulte a mensagem acima; se persistir, verifique os logs do backend-worker."
	}
}

// ScanStatusResponse é o formato público de application.ScanStatus —
// consultado pela UI depois de disparar um scan (ver
// Handlers.GetScanStatus), pra mostrar não só os achados de quem teve
// sucesso mas também, pela primeira vez, qual scanner falhou, de que
// tipo foi o erro e como corrigir — antes desta mudança essa informação
// só existia no log do worker.
type ScanStatusResponse struct {
	JobID             string                   `json:"job_id"`
	Status            string                   `json:"status"`
	Target            string                   `json:"target"`
	RequestedScanners []string                 `json:"requested_scanners"`
	SucceededScanners []string                 `json:"succeeded_scanners"`
	FailedScanners    []ScannerFailureResponse `json:"failed_scanners"`
	Attempts          int                      `json:"attempts"`
	CreatedAt         time.Time                `json:"created_at"`
	StartedAt         *time.Time               `json:"started_at,omitempty"`
	FinishedAt        *time.Time               `json:"finished_at,omitempty"`
}

func toScanStatusResponse(s *application.ScanStatus) ScanStatusResponse {
	return ScanStatusResponse{
		JobID:             s.JobID.String(),
		Status:            s.Status,
		Target:            s.Target,
		RequestedScanners: s.RequestedScanners,
		SucceededScanners: s.SucceededScanners,
		FailedScanners:    toScannerFailureResponses(s.FailedScanners),
		Attempts:          s.Attempts,
		CreatedAt:         s.CreatedAt,
		StartedAt:         s.StartedAt,
		FinishedAt:        s.FinishedAt,
	}
}
