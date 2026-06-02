package redact_test

import (
	"strings"
	"testing"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/events"
	"runtime-guard/internal/llm"
	"runtime-guard/internal/redact"
)

func TestRedactString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "password flag",
			input: "--password=supersecret",
			want:  "--password=[REDACTED]",
		},
		{
			name:  "bearer header",
			input: "Authorization: Bearer abc123",
			want:  "[REDACTED]",
		},
		{
			name:  "url query token",
			input: "https://example.com/download?token=abc123&keep=1",
			want:  "https://example.com/download?keep=1&token=%5BREDACTED%5D",
		},
		{
			name:  "url userinfo",
			input: "https://user:pass@example.com/path",
			want:  "https://%5BREDACTED%5D:%5BREDACTED%5D@example.com/path",
		},
		{
			name:  "env style assignment",
			input: "API_KEY=abcdef",
			want:  "API_KEY=[REDACTED]",
		},
		{
			name:  "api key header",
			input: "X-API-Key: abcdef",
			want:  "[REDACTED]",
		},
		{
			name:  "split password in command string",
			input: "curl --password supersecret https://example.com",
			want:  "curl --password [REDACTED] https://example.com",
		},
		{
			name:  "split curl user in command string",
			input: "curl -u user:supersecret https://example.com",
			want:  "curl -u [REDACTED] https://example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := redact.RedactString(test.input); got != test.want {
				t.Fatalf("RedactString(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestRedactCommandLineHandlesSplitSensitiveArguments(t *testing.T) {
	commandLine := []string{
		"curl",
		"--password", "supersecret",
		"-H", "X-API-Key: abcdef",
		"-u", "user:password",
		"https://example.com/?token=abcdef",
	}
	redacted := redact.RedactCommandLine(commandLine)
	joined := strings.Join(redacted, " ")
	for _, forbidden := range []string{"supersecret", "abcdef", "user:password"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("redacted command line still contains %q: %q", forbidden, joined)
		}
	}
}

func TestRedactEventIncidentAndReport(t *testing.T) {
	event := events.Event{
		EventID:        "evt-1",
		ProcessName:    "curl",
		ExecutablePath: "/usr/bin/curl",
		CommandLine:    []string{"curl", "https://example.com/?token=abc123"},
		FilePath:       "/tmp/passwords.txt",
		Metadata: map[string]any{
			"api_key": "secret",
			"nested": map[string]any{
				"password": "still-secret",
			},
		},
	}
	redactedEvent := redact.Event(event)
	for _, forbidden := range []string{"abc123", "secret", "still-secret"} {
		if strings.Contains(strings.Join(redactedEvent.CommandLine, " "), forbidden) {
			t.Fatalf("redacted command line still contains %q", forbidden)
		}
		if strings.Contains(redactedEvent.FilePath, forbidden) {
			t.Fatalf("redacted file path still contains %q", forbidden)
		}
	}
	if redactedEvent.Metadata["api_key"] != "[REDACTED]" {
		t.Fatalf("metadata redaction = %#v, want [REDACTED]", redactedEvent.Metadata["api_key"])
	}

	incident := compress.Incident{
		IncidentID: "inc-1",
		RootProcess: compress.RootProcess{
			ProcessName:    "curl",
			ExecutablePath: "/usr/bin/curl?token=abc123",
		},
		ProcessTree: []string{"curl -> sh token=abc123"},
		Timeline:    []string{"curl fetched https://example.com/?password=abc123"},
		Summary:     "secret=abc123",
	}
	redactedIncident := redact.Incident(incident)
	if strings.Contains(redactedIncident.Summary, "abc123") {
		t.Fatal("incident summary was not redacted")
	}
	if strings.Contains(redactedIncident.RootProcess.ExecutablePath, "abc123") {
		t.Fatal("incident executable path was not redacted")
	}
	if strings.Contains(redactedIncident.Timeline[0], "abc123") {
		t.Fatal("incident timeline was not redacted")
	}

	report := llm.Report{
		Summary:                    "secret=abc123",
		RiskLevel:                  "medium",
		LikelyBehavior:             "observed token=abc123",
		WhySuspicious:              []string{"api_key=abc123"},
		FalsePositivePossibilities: []string{"password=abc123"},
		RecommendedCommands:        []string{"curl https://example.com/?token=abc123"},
		ContainmentAdvice:          []string{"Bearer abc123"},
	}
	redactedReport := llm.RedactReport(report)
	if strings.Contains(redactedReport.Summary, "abc123") ||
		strings.Contains(redactedReport.LikelyBehavior, "abc123") ||
		strings.Contains(strings.Join(redactedReport.WhySuspicious, " "), "abc123") {
		t.Fatal("LLM report was not redacted")
	}
}

func TestRedactMapHandlesNil(t *testing.T) {
	if got := redact.RedactMap(nil); got != nil {
		t.Fatalf("RedactMap(nil) = %#v, want nil", got)
	}
}

func TestRedactStringLeavesCleanTextAlone(t *testing.T) {
	const clean = "nginx spawned shell sh"
	if got := redact.RedactString(clean); got != clean {
		t.Fatalf("RedactString(%q) = %q, want unchanged", clean, got)
	}
}

func TestRedactStringHandlesDatesAndPathsWithoutSecretMarkers(t *testing.T) {
	input := "2026-06-02 /var/log/nginx/access.log"
	if got := redact.RedactString(input); got != input {
		t.Fatalf("RedactString(%q) = %q, want unchanged", input, got)
	}
}

func TestRedactPromptIncidentProducesJsonFriendlyValues(t *testing.T) {
	incident := compress.Incident{
		IncidentID: "inc-2",
		StartTime:  time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
		EndTime:    time.Date(2026, time.June, 2, 12, 1, 0, 0, time.UTC),
		Summary:    "token=abc123",
	}
	redacted := redact.Incident(incident)
	if strings.Contains(redacted.Summary, "abc123") {
		t.Fatal("prompt incident was not redacted")
	}
}
