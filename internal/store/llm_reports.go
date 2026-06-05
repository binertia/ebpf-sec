package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"tracejutsu/internal/llm"
	"tracejutsu/internal/redact"
)

func (store *SQLite) SaveLLMReport(ctx context.Context, report LLMReport) error {
	if err := validateLLMReport(report); err != nil {
		return fmt.Errorf("save LLM report: %w", err)
	}
	redactedReport := llm.RedactReport(report.Report)
	payload, err := json.Marshal(redactedReport)
	if err != nil {
		return fmt.Errorf("encode LLM report: %w", err)
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin LLM report: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO llm_reports (incident_id, created_at, model, report_json, raw_response)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(incident_id) DO UPDATE SET
    created_at = excluded.created_at,
    model = excluded.model,
    report_json = excluded.report_json,
    raw_response = excluded.raw_response`,
		report.IncidentID, formatTime(report.CreatedAt), report.Model, payload, redact.RedactString(report.RawResponse)); err != nil {
		return fmt.Errorf("save LLM report for incident %q: %w", report.IncidentID, err)
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE incidents SET llm_status = 'complete' WHERE incident_id = ?",
		report.IncidentID)
	if err != nil {
		return fmt.Errorf("mark incident %q LLM status complete: %w", report.IncidentID, err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read incident %q update count: %w", report.IncidentID, err)
	}
	if updated != 1 {
		return fmt.Errorf("mark incident %q LLM status complete: incident not found", report.IncidentID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit LLM report: %w", err)
	}
	return nil
}

func (store *SQLite) GetLLMReport(ctx context.Context, incidentID string) (LLMReport, error) {
	var report LLMReport
	var createdAt string
	var payload []byte
	if err := store.db.QueryRowContext(ctx, `
SELECT incident_id, created_at, model, report_json, raw_response
FROM llm_reports
WHERE incident_id = ?`, incidentID).Scan(
		&report.IncidentID, &createdAt, &report.Model, &payload, &report.RawResponse,
	); err != nil {
		return report, fmt.Errorf("get LLM report %q: %w", incidentID, err)
	}
	var err error
	report.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return report, fmt.Errorf("parse LLM report %q creation time: %w", incidentID, err)
	}
	if err := json.Unmarshal(payload, &report.Report); err != nil {
		return report, fmt.Errorf("decode LLM report %q: %w", incidentID, err)
	}
	if err := llm.ValidateReport(report.Report); err != nil {
		return report, fmt.Errorf("validate stored LLM report %q: %w", incidentID, err)
	}
	report.Report = llm.RedactReport(report.Report)
	report.RawResponse = redact.RedactString(report.RawResponse)
	return report, nil
}

func validateLLMReport(report LLMReport) error {
	switch {
	case report.IncidentID == "":
		return errors.New("incident_id is required")
	case report.CreatedAt.IsZero():
		return errors.New("created_at is required")
	case report.Model == "":
		return errors.New("model is required")
	default:
		return llm.ValidateReport(report.Report)
	}
}
