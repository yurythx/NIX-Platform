package events

import (
	"testing"

	"github.com/google/uuid"
)

type samplePayload struct {
	JobID string `json:"job_id"`
}

func TestNew_BuildsValidEnvelope(t *testing.T) {
	corr := uuid.New()
	ev, err := New("diario_oficial.job.completed", "nix.diario_oficial", corr, samplePayload{JobID: "abc"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if ev.ID == uuid.Nil {
		t.Error("expected non-nil ID")
	}
	if ev.Type != "diario_oficial.job.completed" {
		t.Errorf("Type = %q", ev.Type)
	}
	if ev.Version != EnvelopeVersion {
		t.Errorf("Version = %d, want %d", ev.Version, EnvelopeVersion)
	}
	if ev.Source != "nix.diario_oficial" {
		t.Errorf("Source = %q", ev.Source)
	}
	if ev.OccurredAt.IsZero() {
		t.Error("expected non-zero OccurredAt")
	}
	if ev.CorrelationID != corr {
		t.Errorf("CorrelationID = %v, want %v", ev.CorrelationID, corr)
	}

	var decoded samplePayload
	if err := ev.UnmarshalPayload(&decoded); err != nil {
		t.Fatalf("UnmarshalPayload() error = %v", err)
	}
	if decoded.JobID != "abc" {
		t.Errorf("decoded JobID = %q, want abc", decoded.JobID)
	}
}

func TestNew_GeneratesCorrelationIDWhenNil(t *testing.T) {
	ev, err := New("user.created", "nix.users", uuid.Nil, samplePayload{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if ev.CorrelationID == uuid.Nil {
		t.Error("expected a generated correlation id, got uuid.Nil")
	}
}

func TestNew_RequiresTypeAndSource(t *testing.T) {
	if _, err := New("", "src", uuid.Nil, nil); err == nil {
		t.Error("expected error for empty type")
	}
	if _, err := New("type", "", uuid.Nil, nil); err == nil {
		t.Error("expected error for empty source")
	}
}
