package report

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/detect"
	"tracejutsu/internal/llm"
	"tracejutsu/internal/redact"
)

func Write(writer io.Writer, incident compress.Incident) error {
	incident = redact.Incident(incident)
	if _, err := fmt.Fprintf(writer, "INCIDENT %s  %s  score=%d  %s\n",
		TerminalText(incident.IncidentID),
		strings.ToUpper(detect.RiskLevel(incident.RiskScore)),
		incident.RiskScore,
		incident.StartTime.UTC().Format("2006-01-02T15:04:05Z")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "root: %s(%d)\n\nSignals:\n",
		TerminalText(incident.RootProcess.ProcessName), incident.RootProcess.PID); err != nil {
		return err
	}
	for _, signal := range incident.Signals {
		if _, err := fmt.Fprintf(writer, "  %s\n", TerminalText(signal)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer, "\nTimeline:"); err != nil {
		return err
	}
	for _, entry := range incident.Timeline {
		if _, err := fmt.Fprintf(writer, "  %s\n", TerminalText(entry)); err != nil {
			return err
		}
	}
	if incident.DroppedEvents > 0 {
		if _, err := fmt.Fprintf(writer, "\nDropped during grouping: %d events\n", incident.DroppedEvents); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "\nSummary:\n  %s\n", TerminalText(incident.Summary))
	return err
}

func WriteLLM(writer io.Writer, incident compress.Incident, analysis llm.Report) error {
	incident = redact.Incident(incident)
	analysis = llm.RedactReport(analysis)
	deterministicRisk := detect.RiskLevel(incident.RiskScore)
	if _, err := fmt.Fprintf(writer, "LLM ANALYSIS %s\n", TerminalText(incident.IncidentID)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "deterministic risk: %s (score=%d)\n", deterministicRisk, incident.RiskScore); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "llm risk: %s", TerminalText(analysis.RiskLevel)); err != nil {
		return err
	}
	if analysis.RiskLevel != deterministicRisk {
		if _, err := fmt.Fprint(writer, " (disagrees with deterministic score)"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "\n\nSummary:\n  %s\n\nLikely behavior:\n  %s\n",
		TerminalText(analysis.Summary), TerminalText(analysis.LikelyBehavior)); err != nil {
		return err
	}
	if err := writeList(writer, "Why suspicious", analysis.WhySuspicious); err != nil {
		return err
	}
	if err := writeList(writer, "False positive possibilities", analysis.FalsePositivePossibilities); err != nil {
		return err
	}
	if err := writeList(writer, "Recommended commands", analysis.RecommendedCommands); err != nil {
		return err
	}
	return writeList(writer, "Containment advice", analysis.ContainmentAdvice)
}

func writeList(writer io.Writer, title string, entries []string) error {
	if _, err := fmt.Fprintf(writer, "\n%s:\n", title); err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(writer, "  - %s\n", TerminalText(entry)); err != nil {
			return err
		}
	}
	return nil
}

// TerminalText replaces control and bidirectional formatting characters so
// runtime-controlled text cannot alter terminal state or visually reorder it.
func TerminalText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) ||
			character >= '\u202a' && character <= '\u202e' ||
			character >= '\u2066' && character <= '\u2069' {
			return '?'
		}
		return character
	}, value)
}
