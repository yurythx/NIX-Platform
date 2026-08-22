// Package domain define o contrato de provedor plugável do módulo SecOps
// (§36): VirusTotal hoje, Shodan/AbuseIPDB/MISP/OpenCTI/Wazuh/CrowdSec no
// futuro — nenhum deles exige tocar no Core, só adicionar uma nova
// implementação em infrastructure/<provider> e registrá-la em
// internal/app. É este contrato que torna a plataforma extensível sem
// reescrever o fluxo de teste de integração a cada novo provedor.
package domain

import "context"

// SecCheckResult é o resultado de AnalyzeTarget.
type SecCheckResult struct {
	Success bool
	Summary string
	Details map[string]any
}

// SecurityProvider é implementado por toda integração SecOps.
type SecurityProvider interface {
	Name() string
	TestConnection(ctx context.Context) error
	AnalyzeTarget(ctx context.Context, target string) (*SecCheckResult, error)
}
