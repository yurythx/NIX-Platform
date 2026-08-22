package outbox

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/yurythx/nix-platform/internal/domain/events"
)

func validEnvelopeJSON(t *testing.T) []byte {
	t.Helper()
	event, err := events.New("diario_oficial.job.completed", "nix.test", uuid.New(), map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("events.New: %v", err)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return raw
}

func TestValidateEnvelope_AcceptsAWellFormedEnvelope(t *testing.T) {
	if err := validateEnvelope(validEnvelopeJSON(t)); err != nil {
		t.Fatalf("validateEnvelope rejected a well-formed envelope: %v", err)
	}
}

func TestValidateEnvelope_RejectsMissingRequiredField(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(validEnvelopeJSON(t), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(doc, "correlation_id")
	raw, _ := json.Marshal(doc)

	err := validateEnvelope(raw)
	if err == nil {
		t.Fatal("esperava rejeição de um envelope sem correlation_id")
	}
}

func TestValidateEnvelope_RejectsUnknownAdditionalField(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(validEnvelopeJSON(t), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc["unexpected_field"] = "should not be here"
	raw, _ := json.Marshal(doc)

	err := validateEnvelope(raw)
	if err == nil {
		t.Fatal("esperava rejeição de um envelope com um campo fora do contrato padrão")
	}
}

func TestValidateEnvelope_RejectsNonUUIDId(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(validEnvelopeJSON(t), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc["id"] = "not-a-uuid"
	raw, _ := json.Marshal(doc)

	if err := validateEnvelope(raw); err == nil {
		t.Fatal("esperava rejeição de um id que não é um UUID")
	}
}

func TestValidateEnvelope_RejectsTypeNotFollowingConvention(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(validEnvelopeJSON(t), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc["type"] = "not-following-the-convention"
	raw, _ := json.Marshal(doc)

	err := validateEnvelope(raw)
	if err == nil {
		t.Fatal("esperava rejeição de um type que não segue a convenção <contexto>.<entidade>.<ação>")
	}
	if !strings.Contains(err.Error(), "outbox:") {
		t.Errorf("err = %v, want prefixado com \"outbox:\"", err)
	}
}

func TestValidateEnvelope_RejectsMissingPayloadKey(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(validEnvelopeJSON(t), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(doc, "payload")
	raw, _ := json.Marshal(doc)

	if err := validateEnvelope(raw); err == nil {
		t.Fatal("esperava rejeição de um envelope sem a chave payload")
	}
}

func TestValidateEnvelope_RejectsWrongVersionType(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(validEnvelopeJSON(t), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc["version"] = "1" // string, não integer
	raw, _ := json.Marshal(doc)

	if err := validateEnvelope(raw); err == nil {
		t.Fatal("esperava rejeição de version como string em vez de integer")
	}
}
