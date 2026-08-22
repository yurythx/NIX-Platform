// Package jobs fornece a entidade e o repositório compartilhados de job
// assíncrono (§33), usados por todo módulo que executa trabalho via
// RabbitMQ + um worker (hoje: diario_oficial, integrations/secops). É
// infraestrutura de plataforma, não um módulo de negócio em si — os
// módulos dependem dele, nunca o contrário.
package jobs

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Status é o estado de ciclo de vida de um job (§33/§73). As transições
// são impostas por CanTransition — um job nunca pode pular entre estados
// arbitrários (ex.: ir direto de "queued" para "completed" sem passar por
// "processing").
type Status string

const (
	StatusQueued     Status = "queued"
	StatusProcessing Status = "processing"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusDeadLetter Status = "dead_letter"
)

// validTransitions enumera toda aresta Status -> Status permitida. É o
// mapa que codifica a regra de negócio "que mudanças de estado um job pode
// sofrer" — qualquer transição fora daqui é rejeitada por CanTransition.
var validTransitions = map[Status][]Status{
	StatusQueued:     {StatusProcessing},
	StatusProcessing: {StatusCompleted, StatusFailed},
	StatusFailed:     {StatusProcessing, StatusDeadLetter}, // uma redelivery com retry volta a processar; retries esgotados vão para dead-letter
	StatusCompleted:  {},
	StatusDeadLetter: {},
}

// CanTransition reporta se mover de from para to é uma aresta permitida.
func CanTransition(from, to Status) bool {
	for _, s := range validTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Job é uma unidade de trabalho assíncrono (§33) — o registro persistido
// que representa, por exemplo, "rodar o teste de conectividade do Diário
// Oficial" desde o momento em que a API o cria até o worker terminar de
// processá-lo (com sucesso, falha, ou esgotando os retries).
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

// New constrói um job no estado inicial "queued", serializando payload
// como JSON. O correlationID recebido normalmente é o mesmo da requisição
// HTTP que originou o job, para que toda a cadeia (requisição -> job ->
// evento de outbox -> processamento no worker -> notificação via
// WebSocket) possa ser correlacionada nos logs (§50).
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
