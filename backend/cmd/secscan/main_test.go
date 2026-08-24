package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yurythx/nix-platform/internal/modules/scanning/domain"
)

func TestParseFailOn(t *testing.T) {
	cases := []struct {
		in      string
		want    domain.Severity
		wantErr bool
	}{
		{"HIGH", domain.SeverityHigh, false},
		{"high", domain.SeverityHigh, false}, // case-insensitive
		{"CRITICAL", domain.SeverityCritical, false},
		{"NONE", "", false},
		{"none", "", false},
		{"garbage", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		got, err := parseFailOn(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseFailOn(%q) = nil error, want an error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseFailOn(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseFailOn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasFindingAtOrAbove(t *testing.T) {
	findings := []domain.Finding{
		{Severity: domain.SeverityLow},
		{Severity: domain.SeverityMedium},
	}
	if hasFindingAtOrAbove(findings, domain.SeverityHigh) {
		t.Error("no HIGH/CRITICAL finding present, want false")
	}
	if !hasFindingAtOrAbove(findings, domain.SeverityMedium) {
		t.Error("a MEDIUM finding is present, want true for threshold MEDIUM")
	}
	if !hasFindingAtOrAbove(findings, domain.SeverityLow) {
		t.Error("threshold LOW should match everything")
	}
}

func TestHasFindingAtOrAbove_NoneThresholdNeverTriggers(t *testing.T) {
	findings := []domain.Finding{{Severity: domain.SeverityCritical}}
	if hasFindingAtOrAbove(findings, "") {
		t.Error("empty threshold (--fail-on NONE) should never trigger, even with a CRITICAL finding")
	}
}

func TestHasFindingAtOrAbove_EmptyFindings(t *testing.T) {
	if hasFindingAtOrAbove(nil, domain.SeverityLow) {
		t.Error("no findings at all should never trigger")
	}
}

func TestPrintReport_SortsBySeverityAndSummarizes(t *testing.T) {
	findings := []domain.Finding{
		{ID: "low-1", Severity: domain.SeverityLow, Description: "achado baixo", File: "a.go"},
		{ID: "crit-1", Severity: domain.SeverityCritical, Description: "achado crítico", File: "b.go", Line: 42},
	}
	var buf bytes.Buffer
	printReport(&buf, findings)
	out := buf.String()

	critIdx := strings.Index(out, "crit-1")
	lowIdx := strings.Index(out, "low-1")
	if critIdx == -1 || lowIdx == -1 {
		t.Fatalf("report missing an expected finding, got: %s", out)
	}
	if critIdx > lowIdx {
		t.Errorf("CRITICAL finding should be printed before LOW, got: %s", out)
	}
	if !strings.Contains(out, "b.go:42") {
		t.Errorf("report should include file:line for a finding with a line number, got: %s", out)
	}
	if !strings.Contains(out, "2 finding(s)") {
		t.Errorf("report should summarize the total count, got: %s", out)
	}
}

func TestPrintReport_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	printReport(&buf, nil)
	if !strings.Contains(buf.String(), "no findings") {
		t.Errorf("expected a clean-scan message, got: %s", buf.String())
	}
}

func TestSplitAndTrim(t *testing.T) {
	got := splitAndTrim(" trivy, semgrep ,,")
	want := []string{"trivy", "semgrep"}
	if len(got) != len(want) {
		t.Fatalf("splitAndTrim = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("splitAndTrim = %v, want %v", got, want)
		}
	}
}

func TestRun_NoScanArgument_ReturnsUsageExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{}, &stdout, &stderr)
	if code != exitUsageOrTool {
		t.Errorf("run with no arguments = exit %d, want %d", code, exitUsageOrTool)
	}
}

func TestRun_InvalidFailOn_ReturnsUsageExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"scan", "--fail-on", "not-a-severity"}, &stdout, &stderr)
	if code != exitUsageOrTool {
		t.Errorf("run with an invalid --fail-on = exit %d, want %d", code, exitUsageOrTool)
	}
}

func TestRun_UnsupportedScanner_ReturnsUsageExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"scan", "--scanners", "sonarqube"}, &stdout, &stderr)
	if code != exitUsageOrTool {
		t.Errorf("run with an unsupported scanner (sonarqube needs a live server) = exit %d, want %d", code, exitUsageOrTool)
	}
	if !strings.Contains(stderr.String(), "sonarqube") {
		t.Errorf("stderr should explain which scanner is unsupported, got: %s", stderr.String())
	}
}
