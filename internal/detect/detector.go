package detect

import "tracejutsu/internal/events"

type Signal struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	ScoreImpact int      `json:"score_impact"`
	EventIDs    []string `json:"event_ids"`
	Evidence    string   `json:"evidence"`
}

type Result struct {
	Signals   []Signal `json:"signals"`
	RiskScore int      `json:"risk_score"`
}

type Detector interface {
	Analyze(normalizedEvents []events.Event) Result
}

func RiskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}
