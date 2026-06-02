package store

import (
	"context"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/events"
	"runtime-guard/internal/llm"
)

type LLMReport struct {
	IncidentID  string
	CreatedAt   time.Time
	Model       string
	Report      llm.Report
	RawResponse string
}

// Store is intentionally small so SQLite can be added without coupling the
// event pipeline to database details.
type Store interface {
	SaveEvent(ctx context.Context, event events.Event) error
	SaveIncident(ctx context.Context, incident compress.Incident) error
	LinkIncidentEvents(ctx context.Context, incidentID string, eventIDs []string) error
	SaveIncidentWithEvents(ctx context.Context, incident compress.Incident, normalizedEvents []events.Event) error
	SaveLLMReport(ctx context.Context, report LLMReport) error
}
