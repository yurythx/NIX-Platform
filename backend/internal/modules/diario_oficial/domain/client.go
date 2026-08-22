// Package domain holds the diario_oficial module's contract with the
// external Diário Oficial system. The real HTTP implementation lives in
// infrastructure/ — this package knows nothing about HTTP, RabbitMQ, or
// PostgreSQL.
package domain

import "context"

// CheckResult is the outcome of a successful Diário Oficial check.
type CheckResult struct {
	StatusCode int
	Summary    string
}

// Client abstracts the external Diário Oficial system so the module's
// application logic is testable without a live endpoint.
type Client interface {
	Check(ctx context.Context) (*CheckResult, error)
}
