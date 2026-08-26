// Package transport implementa os handlers HTTP do módulo scanning:
// disparar um scan assíncrono (POST) e consultar seus achados (GET). Nunca
// executa um CodeScanner diretamente — CreateScanJob só cria o job e seu
// evento de outbox disparador; a execução de fato acontece no worker (ver
// scanning/worker), rodando todo scanner pedido em paralelo (Fase 7 —
// Orquestração concorrente).
package transport

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/application"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
	"github.com/yurythx/nix-platform/internal/platform/auth"
	"github.com/yurythx/nix-platform/internal/platform/httpserver"
	"github.com/yurythx/nix-platform/internal/platform/jobs"
	"github.com/yurythx/nix-platform/internal/platform/logging"
	"github.com/yurythx/nix-platform/pkg/httputil"
)

type Handlers struct {
	service *application.Service
	logger  *slog.Logger
	// sonarQubePublicURL é o endereço que o NAVEGADOR do usuário
	// consegue abrir (SCANNING_SONARQUBE_PUBLIC_URL) — diferente do
	// endereço interno que o worker usa pra falar com o servidor. Usado
	// só pra montar o link "abrir no SonarQube" de um achado (ver
	// dto.go's toolLink); vazio simplesmente omite esse link.
	sonarQubePublicURL string
}

func NewHandlers(service *application.Service, logger *slog.Logger, sonarQubePublicURL string) *Handlers {
	return &Handlers{service: service, logger: logger, sonarQubePublicURL: sonarQubePublicURL}
}

// createScanRequest aceita um ou mais scanners — mais de um dispara todos
// em paralelo contra o mesmo alvo, sob o mesmo job/scan_id (Fase 7).
// ProjectID (Fase 10) é opcional — quando presente, dispara um scan a
// partir de um domain.Project já existente ("Rodar de novo" no frontend)
// em vez de um alvo avulso; Target é ignorado nesse caso (o alvo vem do
// próprio projeto).
type createScanRequest struct {
	Scanners  []string `json:"scanners"`
	Target    string   `json:"target"`
	ProjectID string   `json:"project_id,omitempty"`
}

type scanJobResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// CreateScan trata POST /api/v1/scanning/scans. Só cria o job e retorna
// 202 — o clone/scan de fato acontece de forma assíncrona no worker, e o
// resultado chega ao frontend via WebSocket (scanning.scan.completed /
// scanning.scan.failed). job_id retornado aqui é o mesmo scan_id usado
// depois em GET .../scans/{scan_id}/findings.
func (h *Handlers) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	correlationID := correlationIDFromRequest(r)

	var requestedBy *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			requestedBy = &id
		}
	}

	var (
		job *jobs.Job
		err error
	)
	if req.ProjectID != "" {
		projectID, parseErr := uuid.Parse(req.ProjectID)
		if parseErr != nil {
			httputil.WriteError(w, r, h.logger, apperrors.BadRequest("project_id must be a valid UUID"))
			return
		}
		job, err = h.service.CreateProjectScanJob(r.Context(), correlationID, req.Scanners, projectID, requestedBy)
	} else {
		job, err = h.service.CreateScanJob(r.Context(), correlationID, req.Scanners, req.Target, requestedBy)
	}
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteAccepted(w, scanJobResponse{JobID: job.ID.String(), Status: string(job.Status)})
}

// ListFindings trata GET /api/v1/scanning/scans/{scanID}/findings.
func (h *Handlers) ListFindings(w http.ResponseWriter, r *http.Request) {
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

	httputil.WriteOK(w, toFindingResponses(findings, h.sonarQubePublicURL))
}

// ListPackages trata GET /api/v1/scanning/scans/{scanID}/packages — o
// inventário (Fase 11 — Syft) de uma execução, sempre vazio pra um scan
// que não pediu o scanner "syft" (nenhum outro scanner grava em
// scan_packages).
func (h *Handlers) ListPackages(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "scanID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("scanID must be a valid UUID"))
		return
	}

	packages, err := h.service.ListPackages(r.Context(), scanID)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toPackageResponses(packages))
}

// GetScanStatus trata GET /api/v1/scanning/scans/{scanID} — pensado pra
// UI fazer polling logo depois de CreateScan até o status virar terminal
// (completed/failed/dead_letter), e então mostrar não só os achados
// (ListFindings) mas também qual scanner falhou, de que tipo foi o erro
// e como corrigir (ver ScanStatusResponse/remediationHint) — resposta
// direta ao pedido do usuário de saber "qual ferramenta achou o erro" e
// separar os erros por tipo/correção, que antes só existia no log do
// worker.
func (h *Handlers) GetScanStatus(w http.ResponseWriter, r *http.Request) {
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

	httputil.WriteOK(w, toScanStatusResponse(status))
}

// ListScans trata GET /api/v1/scanning/scans — a lista de execuções
// recentes que /seguranca usa pra mostrar "resultados separados por
// scan" (cada disparo como sua própria entrada, status e progresso
// próprios) em vez de só o feed de achados misturando todo scan junto
// (ver ListRecentFindings). Cada entrada é o mesmo ScanStatusResponse de
// GetScanStatus — clicar numa entrada nesta lista e consultar
// GET .../scans/{id} depois nunca mostra um formato diferente.
func (h *Handlers) ListScans(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	scans, err := h.service.ListRecentScans(r.Context(), limit)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toScanStatusResponses(scans))
}

// ListRecentFindings trata GET /api/v1/scanning/findings — o feed "achados
// recentes por severidade" (Fase 9) usado pela UI, que não exige um
// scan_id de antemão como ListFindings exige.
//
// page/page_size (Fase 14 — Maturidade de AppSec): antes só "limit"
// existia, sem OFFSET — passado disso, o resto simplesmente nunca
// aparecia em lugar nenhum da UI. "limit" continua aceito como um alias
// de page_size (compatibilidade com qualquer chamador antigo que ainda
// use o nome velho) quando page_size não vem explícito.
func (h *Handlers) ListRecentFindings(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize == 0 {
		pageSize, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	}

	findings, meta, err := h.service.ListRecentFindings(r.Context(), page, pageSize)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOKWithMeta(w, toFindingResponses(findings, h.sonarQubePublicURL), meta)
}

// maxUploadRequestBytes limita o corpo INTEIRO de uma requisição
// multipart (o .zip + qualquer overhead de form) — folga acima do teto
// do próprio .zip (application.maxUploadZipBytes) pra sobrar espaço pro
// resto do multipart sem apertar o limite do arquivo em si.
const maxUploadRequestBytes = 55 * 1024 * 1024 // 55MB

// createProjectGitRequest é o corpo JSON aceito por POST
// /api/v1/scanning/projects quando o projeto aponta pra um alvo git —
// multipart/form-data é o outro formato aceito (ver CreateProject), pra
// upload de um .zip.
type createProjectGitRequest struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// CreateProject trata POST /api/v1/scanning/projects (Fase 10) — aceita
// dois formatos de corpo, escolhidos pelo Content-Type: application/json
// {name, target} pra um projeto git, ou multipart/form-data (campo de
// texto "name" + arquivo "file") pra um projeto criado por upload de um
// .zip. Nunca dispara nenhum scan — só cria o registro; o disparo em si
// continua sendo POST /api/v1/scanning/scans com project_id preenchido
// (ver CreateScan), o mesmo endpoint que um scan avulso já usa.
func (h *Handlers) CreateProject(w http.ResponseWriter, r *http.Request) {
	var requestedBy *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			requestedBy = &id
		}
	}

	var (
		project *domain.Project
		err     error
	)

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		project, err = h.createProjectFromUpload(w, r, requestedBy)
	} else {
		var req createProjectGitRequest
		if decodeErr := httputil.DecodeJSON(w, r, &req); decodeErr != nil {
			httputil.WriteError(w, r, h.logger, decodeErr)
			return
		}
		project, err = h.service.CreateProjectGit(r.Context(), req.Name, req.Target, requestedBy)
	}
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteCreated(w, toProjectResponse(*project, nil))
}

// createProjectFromUpload lê o campo de texto "name" e o arquivo "file"
// de um corpo multipart/form-data — o outro caminho de CreateProject.
func (h *Handlers) createProjectFromUpload(w http.ResponseWriter, r *http.Request, requestedBy *uuid.UUID) (*domain.Project, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadRequestBytes)
	if err := r.ParseMultipartForm(maxUploadRequestBytes); err != nil {
		return nil, apperrors.BadRequest(fmt.Sprintf("invalid multipart/form-data body: %v", err))
	}

	name := r.FormValue("name")
	file, _, err := r.FormFile("file")
	if err != nil {
		return nil, apperrors.BadRequest(`missing "file" field with the .zip upload`)
	}
	defer file.Close()

	zipBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, apperrors.BadRequest(fmt.Sprintf("failed to read uploaded file: %v", err))
	}

	return h.service.CreateProjectUpload(r.Context(), name, zipBytes, requestedBy)
}

// ListProjects trata GET /api/v1/scanning/projects (Fase 10) — cada
// projeto vem com o status do último scan embutido (LastScan), quando
// já rodou algum, pra "/seguranca" mostrar isso direto no card sem uma
// segunda viagem por projeto.
func (h *Handlers) ListProjects(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	projects, err := h.service.ListProjects(r.Context(), limit)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	lastScanByProject := make(map[string]*application.ScanStatus, len(projects))
	for _, p := range projects {
		scans, err := h.service.ListProjectScans(r.Context(), p.ID)
		if err != nil {
			// Best-effort: histórico de scan é um complemento do card, não
			// o projeto em si — uma falha aqui não deveria impedir a
			// listagem inteira de projetos de responder.
			h.logger.Warn("scanning: failed to load last scan for project (best-effort)",
				slog.String("project_id", p.ID.String()), slog.Any("error", err))
			continue
		}
		if len(scans) > 0 {
			lastScanByProject[p.ID.String()] = scans[0]
		}
	}

	httputil.WriteOK(w, toProjectResponses(projects, lastScanByProject))
}

// ListProjectFindingsHistory trata
// GET /api/v1/scanning/projects/{projectID}/findings-history (Fase 12) —
// todo achado deduplicado por fingerprint entre TODOS os scans de um
// projeto, "ainda presente"/"quando apareceu pela primeira vez" incluído.
func (h *Handlers) ListProjectFindingsHistory(w http.ResponseWriter, r *http.Request) {
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

	httputil.WriteOK(w, toProjectFindingHistoryResponses(history))
}

// SecurityPosture trata GET /api/v1/scanning/posture (Fase 14 —
// Maturidade de AppSec) — o resumo agregado de achados abertos entre
// todo projeto, pro card de postura de segurança do dashboard.
func (h *Handlers) SecurityPosture(w http.ResponseWriter, r *http.Request) {
	posture, err := h.service.SecurityPosture(r.Context())
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}
	httputil.WriteOK(w, toSecurityPostureResponse(posture))
}

// PostureHistory trata GET /api/v1/scanning/posture/history (Fase 14,
// continuação — tendência histórica) — a série temporal que
// SecurityPosture sozinho não respondia ("estamos melhorando ou
// piorando?"), gravada periodicamente pelo worker (ver
// application.Service.SnapshotSecurityPosture).
func (h *Handlers) PostureHistory(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))

	snapshots, err := h.service.PostureHistory(r.Context(), days)
	if err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, toPostureSnapshotResponses(snapshots))
}

// ScannersHealth trata GET /api/v1/scanning/scanners/health (revisão de
// exibição de resultados) — checa todo scanner registrado que sabe se
// auto-checar (ver domain.HealthChecker), em paralelo. Pensado pra uma
// tela que o usuário olha ANTES de disparar um scan novo, não durante
// um scan em andamento.
func (h *Handlers) ScannersHealth(w http.ResponseWriter, r *http.Request) {
	health := h.service.CheckScannersHealth(r.Context())
	httputil.WriteOK(w, toScannerHealthResponses(health))
}

// triageFindingRequest é o corpo de PUT
// .../projects/{projectID}/findings/{fingerprint}/triage (Fase 14 —
// Maturidade de AppSec). Reason é obrigatório — validado de novo em
// application.Service.TriageFinding (a mesma regra não pode depender só
// da camada HTTP, ver §33), mas rejeitado aqui também com uma mensagem
// específica de "campo faltando" em vez de deixar a validação de
// domínio genérica ser a primeira a reclamar. ExpiresAt é opcional —
// ponteiro pra RFC 3339, nil quando o campo vem ausente/vazio, "sem
// prazo" continua sendo o comportamento padrão.
type triageFindingRequest struct {
	Status    string     `json:"status"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type triageResponse struct {
	Status string `json:"status"`
}

// TriageFinding trata PUT
// /api/v1/scanning/projects/{projectID}/findings/{fingerprint}/triage —
// marca um achado deduplicado (ver ListProjectFindingsHistory, Fase 12)
// como falso positivo/não vou corrigir/risco aceito. Chamar de novo no
// mesmo fingerprint SUBSTITUI a decisão anterior (ver
// domain.TriageRepository.UpsertTriage) — não é preciso "reabrir" antes
// de trocar de status.
func (h *Handlers) TriageFinding(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("projectID must be a valid UUID"))
		return
	}
	fingerprint := chi.URLParam(r, "fingerprint")

	var req triageFindingRequest
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	var actorUserID *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			actorUserID = &id
		}
	}

	if err := h.service.TriageFinding(r.Context(), projectID, fingerprint, domain.TriageStatus(req.Status), req.Reason, actorUserID, req.ExpiresAt); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, triageResponse{Status: req.Status})
}

// UntriageFinding trata DELETE
// /api/v1/scanning/projects/{projectID}/findings/{fingerprint}/triage —
// "reabre" um achado já triado. Idempotente: chamar num fingerprint que
// nunca foi triado (ou já foi reaberto) não é erro, mesmo princípio de
// domain.TriageRepository.DeleteTriage.
func (h *Handlers) UntriageFinding(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		httputil.WriteError(w, r, h.logger, apperrors.BadRequest("projectID must be a valid UUID"))
		return
	}
	fingerprint := chi.URLParam(r, "fingerprint")

	var actorUserID *uuid.UUID
	if identity, ok := auth.IdentityFromContext(r.Context()); ok {
		if id, err := uuid.Parse(identity.Subject); err == nil {
			actorUserID = &id
		}
	}

	if err := h.service.UntriageFinding(r.Context(), projectID, fingerprint, actorUserID); err != nil {
		httputil.WriteError(w, r, h.logger, err)
		return
	}

	httputil.WriteOK(w, triageResponse{Status: ""})
}

// correlationIDFromRequest reaproveita o request id (§50) como o
// correlation id do fluxo de negócio quando ele já é um UUID, voltando
// para um novo UUID caso o cliente tenha enviado um X-Request-ID que não
// é um UUID — mesmo padrão de diario_oficial/transport/handlers.go.
func correlationIDFromRequest(r *http.Request) uuid.UUID {
	if id, err := uuid.Parse(logging.RequestID(r.Context())); err == nil {
		return id
	}
	return uuid.New()
}

// RateLimitKey limita a criação de scans por usuário autenticado, caindo
// de volta para o IP remoto se a requisição não estiver autenticada (não
// deveria acontecer nesta rota, que exige autenticação, mas serve de
// defesa extra) — mesmo padrão de diario_oficial.
func RateLimitKey(r *http.Request) string {
	if identity, ok := auth.IdentityFromContext(r.Context()); ok && identity.Subject != "" {
		return identity.Subject
	}
	return httpserver.ClientIPKey(r)
}
