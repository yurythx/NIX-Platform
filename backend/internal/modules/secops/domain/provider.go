// Package domain defines the SecOps module's pluggable provider contract
// (§36): VirusTotal today, Shodan/AbuseIPDB/MISP/OpenCTI/Wazuh/CrowdSec
// later — none of them require touching the Core, only adding a new
// infrastructure/<provider> implementation and registering it in
// internal/app.
package domain

import "context"

// SecCheckResult is the outcome of AnalyzeTarget.
type SecCheckResult struct {
	Success bool
	Summary string
	Details map[string]any
}

// SecurityProvider is implemented by every SecOps integration.
type SecurityProvider interface {
	Name() string
	TestConnection(ctx context.Context) error
	AnalyzeTarget(ctx context.Context, target string) (*SecCheckResult, error)
}
