// Arquivo health_check.go (revisão de exibição de resultados — "quero
// ter uma tela onde mostra a saúde das ferramentas... antes de
// iniciá-las"): sidecarHealthCheck é o miolo compartilhado por
// TrivyScanner/GitleaksScanner/SyftScanner/SemgrepScanner/SonarScanner —
// os cinco sidecars (ver cmd/*-sidecar/main.go) expõem exatamente o
// mesmo GET /health (200 sem corpo relevante), então checar "está vivo"
// é idêntico pros cinco; só o nome no erro muda. ZapScanner não usa
// isto — o ZAP não tem um sidecar próprio desta plataforma, é checado
// direto pela API real dele (ver zap_scanner.go's HealthCheck).
package infrastructure

import (
	"context"
	"fmt"
	"net/http"
)

// sidecarHealthCheck não define seu próprio timeout — quem chama
// (application.Service.CheckScannersHealth) já embrulha ctx num
// context.WithTimeout curto por scanner, pra a tela "antes de iniciar"
// nunca travar esperando um sidecar que nunca vai responder.
func sidecarHealthCheck(ctx context.Context, client *http.Client, sidecarURL, scannerName string) error {
	if sidecarURL == "" {
		return fmt.Errorf("scanning: %s: sidecar URL not configured", scannerName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sidecarURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("scanning: %s: build health check request: %w", scannerName, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("scanning: %s: sidecar unreachable: %w", scannerName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scanning: %s: sidecar returned status %d", scannerName, resp.StatusCode)
	}
	return nil
}
