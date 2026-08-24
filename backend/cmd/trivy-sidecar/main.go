// Sidecar HTTP fino em volta do binário `trivy` — roda no PRÓPRIO
// container (ver docker-compose.yml, serviço `trivy-scanner`), isolado
// do backend-worker. Decisão do usuário: "gitguard usa cada solução
// containerizada, vamos fazer do mesmo jeito" — o mesmo padrão que
// SonarQube/ZAP já usam (um serviço de vida longa com API HTTP), agora
// estendido pro Trivy também, em vez de instalar o binário dentro da
// imagem do worker e chamar via os/exec (ver
// docs/roadmap-secops-orchestrator.md, seção "Containerização").
//
// Recebe só um PATH, dentro do volume compartilhado `scanning_workspace`
// (montado somente-leitura aqui — o worker é quem escreve o clone, este
// sidecar só lê) — nunca clona nada sozinho, nunca decide o que é um
// alvo válido (essa validação de SSRF/formato continua só no
// backend-worker, git_clone.go). Devolve o JSON NATIVO do `trivy fs`,
// sem reinterpretar nada — todo o parsing/mapeamento OWASP/normalização
// de severidade continua em trivy_scanner.go, no backend-worker, pra não
// duplicar essa lógica em dois binários.
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

// workspaceRoot é o único lugar de onde este sidecar aceita escanear —
// defesa em profundidade: mesmo que o worker (ou um bug) peça um path
// fora do volume compartilhado, o sidecar recusa antes de rodar
// qualquer coisa, em vez de confiar cegamente no que a rede interna
// mandou. var, não const: main_test.go substitui por um diretório
// temporário de teste, já que "/workspace" só existe de verdade dentro
// do container em produção.
var workspaceRoot = "/workspace"

type scanRequest struct {
	Path string `json:"path"`
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
	logger.Info("trivy-sidecar: listening", slog.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("trivy-sidecar: server stopped", slog.Any("error", err))
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

		// r.Context() é cancelado se o worker (o cliente HTTP) desistir
		// ou fechar a conexão — nenhum timeout próprio precisa ser
		// somado aqui, o chamador já controla o dele (mesmo
		// CloneTimeout/ScanTimeout que todo scanner desta plataforma já
		// respeita).
		cmd := exec.CommandContext(r.Context(), "trivy", "fs", "--format", "json", "--scanners", "vuln,misconfig", "--quiet", req.Path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			logger.Warn("trivy-sidecar: scan failed", slog.String("path", req.Path), slog.String("stderr", stderr.String()))
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
