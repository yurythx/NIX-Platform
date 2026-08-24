// Sidecar HTTP fino em volta do binário `syft` — mesmo padrão de
// cmd/trivy-sidecar/cmd/gitleaks-sidecar (ver
// docs/roadmap-secops-orchestrator.md, seção "Containerização"): roda no
// PRÓPRIO container (docker-compose.yml, serviço `syft-scanner`), só lê o
// volume compartilhado `scanning_workspace`, nunca clona nada sozinho.
// Devolve o JSON NATIVO do `syft scan ... -o json`, sem reinterpretar
// nada — todo o parsing continua em syft_scanner.go, no backend-worker.
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
// var, não const: main_test.go aponta pra um t.TempDir() em vez do
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
	logger.Info("syft-sidecar: listening", slog.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("syft-sidecar: server stopped", slog.Any("error", err))
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

		cmd := exec.CommandContext(r.Context(), "syft", "scan", "dir:"+req.Path, "-o", "json")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			logger.Warn("syft-sidecar: scan failed", slog.String("path", req.Path), slog.String("stderr", stderr.String()))
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
