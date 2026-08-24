package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"time"

	apperrors "github.com/yurythx/nix-platform/internal/domain/errors"
	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

// SyftScannerName é o valor que identifica este CodeScanner no registro do
// scanning.Service.
const SyftScannerName = "syft"

// SyftScanner (Fase 11 — ver docs/roadmap-secops-orchestrator.md, seção
// "Extensão") é ESTRUTURALMENTE DIFERENTE dos outros CodeScanner desta
// plataforma: os outros produzem []domain.Finding (uma vulnerabilidade é
// sempre acionável, algo pra corrigir); o Syft produz um INVENTÁRIO (lista
// de pacotes/versões/licenças), nunca um achado de segurança por si só —
// forçar isso dentro de domain.Finding perderia a informação real, um
// pacote não é um "erro". Por isso Execute (o método que domain.CodeScanner
// exige) é sempre um no-op — SyftScanner nunca aparece na lista de achados
// de nenhum scan. O trabalho real acontece em Inventory
// (domain.InventoryProvider, uma segunda interface OPCIONAL): o Service
// decide via type assertion (scanner.(domain.InventoryProvider)) se chama
// Inventory além de Execute — ver application/service.go's inventoryFor.
//
// Mesmo esqueleto de containerização do GitleaksScanner/TrivyScanner:
// Inventory clona pro volume compartilhado scanning_workspace e chama o
// sidecar `syft-scanner` (cmd/syft-sidecar) via HTTP; InventoryLocal roda o
// binário local via os/exec, sem rede — mesmo par Execute/ExecuteLocal que
// os outros scanners já seguem, só com o nome do método trocado pra deixar
// claro que produz inventário, não achado.
type SyftScanner struct {
	// syftPath só é usado por InventoryLocal.
	syftPath string
	// serviceURL é o endereço do sidecar (ex.: http://syft-scanner:8080)
	// que Inventory chama via HTTP — vazio faz Inventory devolver
	// DependencyUnavailable, mesmo princípio de TrivyScanner.serviceURL
	// vazio.
	serviceURL string
	// workspaceDir é o diretório BASE (dentro do volume compartilhado com
	// o sidecar) onde Inventory clona o alvo — ver cloneShallow.
	workspaceDir string
	httpClient   *http.Client
	cloneTimeout time.Duration
	logger       *slog.Logger
}

// NewSyftScanner constrói o adapter — mesmos parâmetros e mesmo
// significado de NewTrivyScanner/NewGitleaksScanner.
func NewSyftScanner(syftPath, serviceURL, workspaceDir string, cloneTimeout time.Duration, logger *slog.Logger) *SyftScanner {
	return &SyftScanner{
		syftPath:     syftPath,
		serviceURL:   strings.TrimRight(serviceURL, "/"),
		workspaceDir: workspaceDir,
		httpClient:   &http.Client{Timeout: 5 * time.Minute},
		cloneTimeout: cloneTimeout,
		logger:       logger,
	}
}

var _ domain.CodeScanner = (*SyftScanner)(nil)
var _ domain.InventoryProvider = (*SyftScanner)(nil)
var _ domain.LocalScanner = (*SyftScanner)(nil)
var _ domain.LocalInventoryProvider = (*SyftScanner)(nil)

func (s *SyftScanner) Name() string { return SyftScannerName }

// Execute nunca produz achado — ver o comentário do tipo acima. Sempre
// bem-sucedido, nunca clona nada: o clone de verdade acontece em
// Inventory, chamado separadamente pelo Service (application.inventoryFor)
// quando SyftScanner participa de um scan.
func (s *SyftScanner) Execute(context.Context, string) ([]domain.Finding, error) {
	return nil, nil
}

// ExecuteLocal, mesmo raciocínio de Execute acima — nunca produz achado.
// Implementado só pra satisfazer domain.LocalScanner (Fase 10 — projeto
// criado por upload .zip): sem isto, o Service rejeitaria "syft" como
// scanner inválido pra um projeto de upload, mesmo Syft já suportando
// perfeitamente esse caso via InventoryLocal.
func (s *SyftScanner) ExecuteLocal(context.Context, string) ([]domain.Finding, error) {
	return nil, nil
}

// Inventory clona o alvo (raso, um branch só) via cloneShallow pro volume
// compartilhado com o sidecar, e pede pro sidecar rodar `syft scan dir:`
// nesse caminho via HTTP.
func (s *SyftScanner) Inventory(ctx context.Context, target string) ([]domain.Package, error) {
	if s.serviceURL == "" {
		return nil, apperrors.DependencyUnavailable("scanning: syft: SCANNING_SYFT_SERVICE_URL is not configured")
	}

	dir, cleanup, err := cloneShallow(ctx, target, s.cloneTimeout, s.workspaceDir, s.logger)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return s.inventoryRemote(ctx, dir)
}

// InventoryLocal escaneia dir sem clonar nada — mesmo papel de
// TrivyScanner.ExecuteLocal (cmd/secscan, Fase 10/upload .zip). Nunca
// remove dir: quem chama é dono do diretório. Mesma escolha entre
// sidecar e binário local que TrivyScanner.ExecuteLocal/
// GitleaksScanner.ExecuteLocal fazem, pelo mesmo motivo (o binário
// `syft` também não vive na imagem do worker — só no sidecar) — ver o
// comentário em trivy_scanner.go.
func (s *SyftScanner) InventoryLocal(ctx context.Context, dir string) ([]domain.Package, error) {
	if s.serviceURL != "" {
		return s.inventoryRemote(ctx, dir)
	}

	cmd := exec.CommandContext(ctx, s.syftPath, "scan", "dir:"+dir, "-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: syft: scan failed: %s", extractErrorLine(stderr.String())))
	}
	return parseSyftReport(stdout.Bytes())
}

// inventoryRemote pede pro sidecar (cmd/syft-sidecar) rodar `syft scan
// dir:` contra dir, que precisa estar dentro do volume compartilhado que
// os dois containers montam.
func (s *SyftScanner) inventoryRemote(ctx context.Context, dir string) ([]domain.Package, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: dir})
	if err != nil {
		return nil, fmt.Errorf("scanning: syft: encode scan request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serviceURL+"/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("scanning: syft: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: syft: sidecar unreachable: %s", err.Error()))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: syft: read sidecar response: %s", err.Error()))
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		return nil, apperrors.DependencyUnavailable(fmt.Sprintf("scanning: syft: scan failed: %s", extractErrorLine(errResp.Error)))
	}

	return parseSyftReport(respBody)
}

// syftReport é o subconjunto do JSON nativo do syft ("-o json") que este
// adapter usa — ver syft/format/syftjson/model.Document/Package no
// próprio código-fonte do syft.
type syftReport struct {
	Artifacts []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Type     string `json:"type"`
		Licenses []struct {
			Value string `json:"value"`
		} `json:"licenses"`
	} `json:"artifacts"`
}

func parseSyftReport(raw []byte) ([]domain.Package, error) {
	var report syftReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("scanning: syft: decode report: %w", err)
	}

	packages := make([]domain.Package, 0, len(report.Artifacts))
	for _, a := range report.Artifacts {
		packages = append(packages, domain.Package{
			Name:    a.Name,
			Version: a.Version,
			Type:    a.Type,
			License: firstLicense(a.Licenses),
		})
	}
	return packages, nil
}

// firstLicense devolve só a primeira licença declarada — um pacote pode
// ter várias (dual-licensed, ex. "MIT OR Apache-2.0"), mas domain.Package
// guarda só um valor String pra manter a listagem simples; nenhuma licença
// declarada não é erro, só um pacote sem essa informação.
func firstLicense(licenses []struct {
	Value string `json:"value"`
}) string {
	if len(licenses) == 0 {
		return ""
	}
	return licenses[0].Value
}
