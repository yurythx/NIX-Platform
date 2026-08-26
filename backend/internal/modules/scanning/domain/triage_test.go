package domain

import (
	"testing"
	"time"
)

func TestTriage_Expired(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{"sem prazo nunca expira", nil, false},
		{"prazo no futuro não expirou ainda", &future, false},
		{"prazo no passado expirou", &past, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := Triage{ExpiresAt: tc.expiresAt}
			if got := tr.Expired(now); got != tc.want {
				t.Errorf("Expired(%v) = %v, want %v", now, got, tc.want)
			}
		})
	}
}

func TestValidTriageStatus(t *testing.T) {
	cases := map[TriageStatus]bool{
		TriageFalsePositive:  true,
		TriageWontFix:        true,
		TriageRiskAccepted:   true,
		TriageStatus(""):     false,
		TriageStatus("open"): false,
	}
	for status, want := range cases {
		if got := ValidTriageStatus(status); got != want {
			t.Errorf("ValidTriageStatus(%q) = %v, want %v", status, got, want)
		}
	}
}
