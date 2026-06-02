package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/llm"
	"runtime-guard/internal/report"
)

func TestWriteSanitizesTerminalControlCharacters(t *testing.T) {
	incident := compress.Incident{
		IncidentID: "inc-\x1b[2J",
		StartTime:  time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
		RootProcess: compress.RootProcess{
			ProcessName: "payload\nforged",
			PID:         42,
		},
		Signals:  []string{"signal\u202eoverride"},
		Timeline: []string{"payload\tconnected"},
		Summary:  "summary\rrewritten",
	}

	var output bytes.Buffer
	if err := report.Write(&output, incident); err != nil {
		t.Fatal(err)
	}
	assertSafeTerminalOutput(t, output.String())
	for _, expected := range []string{
		"inc-?[2J",
		"payload?forged",
		"signal?override",
		"payload?connected",
		"summary?rewritten",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}
}

func TestWriteLLMSanitizesTerminalControlCharacters(t *testing.T) {
	incident := compress.Incident{IncidentID: "inc-test", RiskScore: 100}
	analysis := llm.Report{
		Summary:                    "summary\x1b[2J",
		RiskLevel:                  "critical",
		LikelyBehavior:             "payload\nforged",
		WhySuspicious:              []string{"reason\tshifted"},
		FalsePositivePossibilities: []string{},
		RecommendedCommands:        []string{"ps\rrewritten"},
		ContainmentAdvice:          []string{},
	}

	var output bytes.Buffer
	if err := report.WriteLLM(&output, incident, analysis); err != nil {
		t.Fatal(err)
	}
	assertSafeTerminalOutput(t, output.String())
	for _, expected := range []string{
		"summary?[2J",
		"payload?forged",
		"reason?shifted",
		"ps?rewritten",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}
}

func assertSafeTerminalOutput(t *testing.T, output string) {
	t.Helper()
	if strings.ContainsRune(output, '\x1b') {
		t.Fatalf("output contains escape character: %q", output)
	}
	if strings.ContainsRune(output, '\u202e') {
		t.Fatalf("output contains bidirectional override: %q", output)
	}
}
