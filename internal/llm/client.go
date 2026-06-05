package llm

import (
	"context"
	"errors"
	"fmt"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/redact"
)

type Report struct {
	Summary                    string   `json:"summary"`
	RiskLevel                  string   `json:"risk_level"`
	LikelyBehavior             string   `json:"likely_behavior"`
	WhySuspicious              []string `json:"why_suspicious"`
	FalsePositivePossibilities []string `json:"false_positive_possibilities"`
	RecommendedCommands        []string `json:"recommended_commands"`
	ContainmentAdvice          []string `json:"containment_advice"`
}

type Analysis struct {
	Report      Report
	Model       string
	RawResponse string
}

// Client accepts compressed incidents only. It must never receive raw event
// streams.
type Client interface {
	Analyze(ctx context.Context, incident compress.Incident) (Analysis, error)
}

func RedactReport(report Report) Report {
	redacted := report
	redacted.Summary = redact.RedactString(report.Summary)
	redacted.LikelyBehavior = redact.RedactString(report.LikelyBehavior)
	redacted.WhySuspicious = redact.RedactStrings(report.WhySuspicious)
	redacted.FalsePositivePossibilities = redact.RedactStrings(report.FalsePositivePossibilities)
	redacted.RecommendedCommands = redact.RedactStrings(report.RecommendedCommands)
	redacted.ContainmentAdvice = redact.RedactStrings(report.ContainmentAdvice)
	return redacted
}

func ValidateReport(report Report) error {
	switch {
	case report.Summary == "":
		return errors.New("summary is required")
	case report.RiskLevel == "":
		return errors.New("risk_level is required")
	case report.LikelyBehavior == "":
		return errors.New("likely_behavior is required")
	case report.WhySuspicious == nil:
		return errors.New("why_suspicious is required")
	case report.FalsePositivePossibilities == nil:
		return errors.New("false_positive_possibilities is required")
	case report.RecommendedCommands == nil:
		return errors.New("recommended_commands is required")
	case report.ContainmentAdvice == nil:
		return errors.New("containment_advice is required")
	}

	switch report.RiskLevel {
	case "low", "medium", "high", "critical":
		return nil
	default:
		return fmt.Errorf("invalid risk_level %q", report.RiskLevel)
	}
}
