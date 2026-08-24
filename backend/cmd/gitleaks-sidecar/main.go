// Sidecar HTTP fino em volta do binário `gitleaks` — mesmo padrão de
// cmd/trivy-sidecar (ver docs/roadmap-secops-orchestrator.md, seção
// "Containerização"): roda no PRÓPRIO container (docker-compose.yml,
// serviço `gitleaks-scanner`), só lê o volume compartilhado
// `scanning_workspace`, nunca clona nada sozinho.
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
	logger.Info("gitleaks-sidecar: listening", slog.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("gitleaks-sidecar: server stopped", slog.Any("error", err))
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

		// --no-git: escaneia os arquivos como estão no disco, não o
		// histórico de commits (o clone já é raso, --depth 1 — não tem
		// histórico completo mesmo, e escanear commit por commit seria
		// um escopo bem maior e mais lento do que o resto desta
		// plataforma cobre). --exit-code 0: gitleaks sai com 1 por
		// padrão quando ACHA segredo — isso não é uma falha da
		// ferramenta, é o resultado esperado; força sempre 0 pra só um
		// exit != 0 real (erro de verdade, ex.: path inválido) cair no
		// branch de erro abaixo. --report-path /dev/stdout: mesmo
		// padrão de captura que o trivy-sidecar já usa, sem arquivo
		// temporário extra pra limpar.
		cmd := exec.CommandContext(r.Context(), "gitleaks", "detect",
			"--source", req.Path,
			"--no-git",
			"--report-format", "json",
			"--report-path", "/dev/stdout",
			"--exit-code", "0",
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			logger.Warn("gitleaks-sidecar: scan failed", slog.String("path", req.Path), slog.String("stderr", stderr.String()))
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
