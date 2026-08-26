// Sidecar HTTP fino em volta do binário `semgrep` — mesmo padrão de
// cmd/trivy-sidecar/cmd/gitleaks-sidecar (ver
// docs/roadmap-secops-orchestrator.md, seção "Containerização"): roda no
// PRÓPRIO container (docker-compose.yml, serviço `semgrep-scanner`), só
// lê o volume compartilhado `scanning_workspace`, nunca clona nada
// sozinho.
//
// Diferença real em relação a trivy-sidecar/gitleaks-sidecar: os dois
// têm argumentos de linha de comando fixos, então só precisam de `path`
// no corpo da requisição. O semgrep precisa também do ruleset a rodar
// (SCANNING_SEMGREP_CONFIG no worker, ex.: "p/owasp-top-ten") — em vez
// de fixar um valor único aqui (o que exigiria reconstruir/reimplantar
// este sidecar pra trocar de ruleset), `config` viaja no corpo da
// requisição a cada chamada, decidido pelo worker (mesmo lugar que já
// decidia isso antes da containerização) — DefaultSemgrepConfig aqui é
// só uma rede de segurança caso um worker mais antigo não mande o campo.
package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// workspaceRoot é o único lugar de onde este sidecar aceita escanear — var,
// não const, pra os testes poderem apontar pra um t.TempDir() em vez do
// /workspace de produção (mesmo padrão de cmd/trivy-sidecar).
var workspaceRoot = "/workspace"

// defaultConfig espelha infrastructure.DefaultSemgrepConfig — duplicado
// aqui (não importado) de propósito: este binário é um `package main`
// standalone, compilado numa imagem separada, e nunca deveria importar
// internal/modules/scanning só por causa de uma constante de string.
const defaultConfig = "p/owasp-top-ten"

type scanRequest struct {
	Path   string `json:"path"`
	Config string `json:"config"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /scan", handleScan(logger))

	const addr = ":8080"
	logger.Info("semgrep-sidecar: listening", slog.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("semgrep-sidecar: server stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

func handleScan(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
			writeError(w, http.StatusBadRequest, `invalid request body: expected {"path": "..."}`)
			return
		}
		if !strings.HasPrefix(req.Path, workspaceRoot+"/") {
			writeError(w, http.StatusBadRequest, "path must be inside "+workspaceRoot)
			return
		}
		config := req.Config
		if config == "" {
			config = defaultConfig
		}

		// r.Context() é cancelado se o worker (o cliente HTTP) desistir
		// ou fechar a conexão — nenhum timeout próprio precisa ser
		// somado aqui, mesmo princípio de trivy-sidecar/gitleaks-sidecar.
		// --quiet suprime a barra de progresso/banner interativo; sem
		// --error, o exit code do semgrep é 0 tanto com quanto sem
		// achados por padrão — "ferramenta falhou" (branch de erro
		// abaixo) e "achou problema" (200 com JSON de achados) precisam
		// continuar distinguíveis pela leitura do JSON no worker, não
		// pelo exit code, mesmo raciocínio já documentado em
		// semgrep_scanner.go antes da containerização.
		cmd := exec.CommandContext(r.Context(), "semgrep", "scan", "--config", config, "--json", "--quiet", req.Path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			logger.Warn("semgrep-sidecar: scan failed", slog.String("path", req.Path), slog.String("config", config), slog.String("stderr", stderr.String()))
			writeError(w, http.StatusUnprocessableEntity, stderr.String())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(stdout.Bytes())
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}
