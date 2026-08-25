// Sidecar HTTP fino em volta do binário `sonar-scanner` — mesmo padrão de
// cmd/trivy-sidecar/cmd/gitleaks-sidecar/cmd/semgrep-sidecar (ver
// docs/roadmap-secops-orchestrator.md, seção "Containerização"): roda no
// PRÓPRIO container (docker-compose.yml, serviço `sonar-scanner-cli`).
//
// Diferença estrutural real em relação aos outros três sidecars — o
// único motivo de este arquivo não ser uma cópia mecânica deles:
//
//  1. Volume COMPARTILHADO EM LEITURA-ESCRITA, não somente-leitura. O
//     `sonar-scanner` CLI escreve `.scannerwork/report-task.txt` DENTRO
//     do próprio `sonar.projectBaseDir` como parte de como a ferramenta
//     funciona — Trivy/Gitleaks/Semgrep só LEEM o diretório clonado e
//     emitem o resultado no stdout, nunca escrevem nada nele. Por isso
//     `scanning_workspace` é montado `:rw` aqui (docker-compose.yml),
//     ao contrário dos outros três — este sidecar nunca apaga nem cria o
//     diretório do clone em si (isso continua sendo responsabilidade do
//     worker), só escreve o subdiretório `.scannerwork/` que o próprio
//     `sonar-scanner` cria.
//  2. O `sonar-scanner` CLI não devolve o resultado da análise — só faz
//     upload de um relatório e sai. O worker precisa do `ceTaskId` (pra
//     depois consultar /api/ce/task do servidor SonarQube até a
//     Compute Engine terminar de processar, e só então buscar os
//     issues) — esse ID é o que este sidecar lê de
//     `.scannerwork/report-task.txt` (escrito por ele mesmo, com
//     permissão de escrita real) e devolve como JSON, em vez do JSON
//     nativo da ferramenta que os outros três sidecars repassam sem
//     reinterpretar.
//  3. host_url/token/project_key viajam no corpo da requisição, decididos
//     pelo worker a cada chamada — mesmo raciocínio de `config` no
//     semgrep-sidecar (nenhum desses três é fixo na imagem do sidecar).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// workspaceRoot é o único lugar de onde este sidecar aceita escanear —
// var, não const, pra os testes poderem apontar pra um t.TempDir() em
// vez do /workspace de produção (mesmo padrão dos outros sidecars).
var workspaceRoot = "/workspace"

type scanRequest struct {
	Path       string `json:"path"`
	HostURL    string `json:"host_url"`
	Token      string `json:"token"`
	ProjectKey string `json:"project_key"`
}

type scanResponse struct {
	CETaskID string `json:"ce_task_id"`
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
	logger.Info("sonar-sidecar: listening", slog.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("sonar-sidecar: server stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

func handleScan(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" || req.HostURL == "" || req.ProjectKey == "" {
			writeError(w, http.StatusBadRequest, `invalid request body: expected {"path", "host_url", "token", "project_key"}`)
			return
		}
		if !strings.HasPrefix(req.Path, workspaceRoot+"/") {
			writeError(w, http.StatusBadRequest, "path must be inside "+workspaceRoot)
			return
		}

		// r.Context() é cancelado se o worker (o cliente HTTP) desistir
		// ou fechar a conexão — mesmo princípio dos outros sidecars.
		// -Dsonar.scm.disabled=true: o clone raso do worker (--depth 1,
		// git_clone.go) não tem histórico completo, então o SCM
		// Publisher do scanner só geraria aviso e trabalho à toa
		// tentando fazer blame de linha por autor.
		cmd := exec.CommandContext(r.Context(), "sonar-scanner",
			"-Dsonar.host.url="+req.HostURL,
			"-Dsonar.token="+req.Token,
			"-Dsonar.projectKey="+req.ProjectKey,
			"-Dsonar.projectBaseDir="+req.Path,
			"-Dsonar.sources=.",
			"-Dsonar.scm.disabled=true",
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			// Verificado contra o servidor real (ver sonar_scanner.go,
			// comentário equivalente de antes desta containerização):
			// sonar-scanner grava ERROR em stderr, não em stdout.
			logger.Warn("sonar-sidecar: scan failed", slog.String("path", req.Path), slog.String("stderr", stderr.String()))
			writeError(w, http.StatusUnprocessableEntity, extractErrorLine(stderr.String()))
			return
		}

		taskID, err := readCETaskID(req.Path)
		if err != nil {
			logger.Warn("sonar-sidecar: scan succeeded but report-task.txt could not be read", slog.String("path", req.Path), slog.Any("error", err))
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(scanResponse{CETaskID: taskID})
	}
}

// readCETaskID lê ".scannerwork/report-task.txt" (formato key=value, uma
// entrada por linha) que o sonar-scanner grava dentro do
// projectBaseDir depois de um upload bem-sucedido — confirmado contra
// uma execução real, não documentado explicitamente pelo SonarQube (ver
// sonar_scanner.go, onde esta mesma lógica vivia antes desta
// containerização — movida pra cá porque agora é este processo, não o
// worker, quem tem acesso de escrita/leitura direto ao arquivo recém-
// criado).
func readCETaskID(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ".scannerwork", "report-task.txt"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && key == "ceTaskId" {
			return value, nil
		}
	}
	return "", errNoCETaskID
}

var errNoCETaskID = errors.New("report-task.txt has no ceTaskId")

// extractErrorLine devolve a primeira linha que pareça um erro de fato
// ("fatal:"/"error:", case-insensitive) ou, na falta de uma, a última
// linha não-vazia — mesma função, mesmo comportamento, que já existe em
// internal/modules/scanning/infrastructure/git_clone.go, reimplementada
// aqui porque cmd/sonar-sidecar é um binário standalone que nunca
// importa o pacote infrastructure.
func extractErrorLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "fatal:") || strings.Contains(lower, "error:") {
			return line
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return "unknown error"
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}
