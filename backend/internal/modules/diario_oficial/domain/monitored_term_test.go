package domain

import (
	"testing"
	"time"
)

func TestMonitoredTerm_Validate(t *testing.T) {
	cases := []struct {
		name    string
		term    MonitoredTerm
		wantErr bool
	}{
		{"valid with OAB", MonitoredTerm{Label: "Dr. Fulano", OABNumber: "419", OABState: "MG"}, false},
		{"valid with process number", MonitoredTerm{Label: "Processo X", ProcessNumber: "50015349420258130351"}, false},
		{"valid with free text", MonitoredTerm{Label: "Empresa Y", FreeText: "Empresa Y Ltda"}, false},
		{"missing label", MonitoredTerm{OABNumber: "419", OABState: "MG"}, true},
		{"OAB number without state", MonitoredTerm{Label: "x", OABNumber: "419"}, true},
		{"OAB state without number", MonitoredTerm{Label: "x", OABState: "MG"}, true},
		{"no criteria at all", MonitoredTerm{Label: "x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.term.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestMonitoredTerm_HasOAB(t *testing.T) {
	if (MonitoredTerm{OABNumber: "419", OABState: "MG"}).HasOAB() != true {
		t.Error("HasOAB() = false, want true when both are set")
	}
	if (MonitoredTerm{OABNumber: "419"}).HasOAB() != false {
		t.Error("HasOAB() = true, want false when OABState is empty")
	}
}

func TestMonitoredTerm_ToSearchQuery(t *testing.T) {
	since := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	term := MonitoredTerm{OABNumber: "419", OABState: "MG", ProcessNumber: "123", FreeText: "texto"}
	q := term.ToSearchQuery(&since, 2, 25)

	if q.OABNumber != "419" || q.OABState != "MG" {
		t.Errorf("ToSearchQuery OAB = %s/%s, want 419/MG", q.OABNumber, q.OABState)
	}
	if q.ProcessNumber != "123" || q.FreeText != "texto" {
		t.Errorf("ToSearchQuery process/text = %s/%s, want 123/texto", q.ProcessNumber, q.FreeText)
	}
	if q.Since == nil || !q.Since.Equal(since) {
		t.Errorf("ToSearchQuery Since = %v, want %v", q.Since, since)
	}
	if q.Page != 2 || q.PageSize != 25 {
		t.Errorf("ToSearchQuery Page/PageSize = %d/%d, want 2/25", q.Page, q.PageSize)
	}
}
