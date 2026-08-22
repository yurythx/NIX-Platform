// Package jobs provides the shared asynchronous-job entity and repository
// (§33) used by every module that runs work via RabbitMQ + a worker
// (diario_oficial, integrations/secops today). It is platform
// infrastructure, not a business module itself — modules depend on it,
// not the other way around.
package jobs

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Status is a job's lifecycle state (§33/§73). Transitions are enforced by
// CanTransition — a job can never jump between arbitrary states.
type Status string

const (
	StatusQueued     Status = "queued"
	StatusProcessing Status = "processing"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusDeadLetter Status = "dead_letter"
)

// validTransitions enumerates every allowed Status -> Status edge.
var validTransitions = map[Status][]Status{
	StatusQueued:     {StatusProcessing},
	StatusProcessing: {StatusCompleted, StatusFailed},
	StatusFailed:     {StatusProcessing, StatusDeadLetter}, // a retried redelivery re-processes; exhausted retries dead-letter it
	StatusCompleted:  {},
	StatusDeadLetter: {},
}

// CanTransition reports whether moving from -> to is an allowed edge.
func CanTransition(from, to Status) bool {
	for _, s := range validTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Job is one unit of asynchronous work (§33).
type Job struct {
	ID            uuid.UUID
	Type          string
	Status        Status
	Attempts      int
	Payload       json.RawMessage
	Result        json.RawMessage
	Error         *string
	CorrelationID uuid.UUID
	CreatedAt     time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
}

// New builds a job in the initial "queued" state.
func New(jobType string, correlationID uuid.UUID, payload any) (*Job, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("jobs: marshal payload: %w", err)
	}
	return &Job{
		ID:            uuid.New(),
		Type:          jobType,
		Status:        StatusQueued,
		Payload:       raw,
		CorrelationID: correlationID,
		CreatedAt:     time.Now().UTC(),
	}, nil
}
