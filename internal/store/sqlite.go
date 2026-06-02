package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/events"
	"runtime-guard/internal/redact"
)

const defaultLimit = 50

type SQLite struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLite, error) {
	if path == "" {
		return nil, errors.New("SQLite path is required")
	}
	if err := prepareSQLitePath(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)

	opened := &SQLite{db: db}
	if err := opened.initialize(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if path != ":memory:" {
		if err := validateSQLiteFile(path); err != nil {
			db.Close()
			return nil, err
		}
	}
	return opened, nil
}

func (store *SQLite) initialize(ctx context.Context) error {
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := store.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("initialize SQLite with %q: %w", pragma, err)
		}
	}
	if _, err := store.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply SQLite schema: %w", err)
	}
	if err := ensureIncidentDroppedEventsColumn(ctx, store.db); err != nil {
		return err
	}
	return nil
}

func (store *SQLite) Close() error {
	return store.db.Close()
}

func (store *SQLite) JournalMode(ctx context.Context) (string, error) {
	var mode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return "", fmt.Errorf("read SQLite journal mode: %w", err)
	}
	return mode, nil
}

func (store *SQLite) SaveEvent(ctx context.Context, event events.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("save event: %w", err)
	}
	if err := insertEvent(ctx, store.db, redact.Event(event)); err != nil {
		return fmt.Errorf("save event %q: %w", event.EventID, err)
	}
	return nil
}

func (store *SQLite) SaveEvents(ctx context.Context, normalizedEvents []events.Event) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin event batch: %w", err)
	}
	defer tx.Rollback()

	for _, event := range normalizedEvents {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("save event %q: %w", event.EventID, err)
		}
		if err := insertEvent(ctx, tx, redact.Event(event)); err != nil {
			return fmt.Errorf("save event %q: %w", event.EventID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit event batch: %w", err)
	}
	return nil
}

func (store *SQLite) SaveIncident(ctx context.Context, incident compress.Incident) error {
	if err := validateIncident(incident); err != nil {
		return fmt.Errorf("save incident: %w", err)
	}
	if err := insertIncident(ctx, store.db, redact.Incident(incident)); err != nil {
		return fmt.Errorf("save incident %q: %w", incident.IncidentID, err)
	}
	return nil
}

func (store *SQLite) LinkIncidentEvents(ctx context.Context, incidentID string, eventIDs []string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin incident event links: %w", err)
	}
	defer tx.Rollback()

	if err := replaceIncidentEventLinks(ctx, tx, incidentID, eventIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit incident event links: %w", err)
	}
	return nil
}

func (store *SQLite) SaveIncidentWithEvents(ctx context.Context, incident compress.Incident, normalizedEvents []events.Event) error {
	if err := validateIncident(incident); err != nil {
		return fmt.Errorf("save incident: %w", err)
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin incident batch: %w", err)
	}
	defer tx.Rollback()

	if err := insertIncident(ctx, tx, redact.Incident(incident)); err != nil {
		return fmt.Errorf("save incident %q: %w", incident.IncidentID, err)
	}
	eventIDs := make([]string, 0, len(normalizedEvents))
	for _, event := range normalizedEvents {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("save incident event %q: %w", event.EventID, err)
		}
		if err := insertEvent(ctx, tx, redact.Event(event)); err != nil {
			return fmt.Errorf("save incident event %q: %w", event.EventID, err)
		}
		eventIDs = append(eventIDs, event.EventID)
	}
	if err := replaceIncidentEventLinks(ctx, tx, incident.IncidentID, eventIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit incident batch: %w", err)
	}
	return nil
}

func (store *SQLite) ListEvents(ctx context.Context, limit int) ([]events.Event, error) {
	rows, err := store.db.QueryContext(ctx, `
SELECT event_id, timestamp, host, container_id, container_name, pid, ppid, uid,
       process_name, parent_process_name, event_type, executable_path,
       command_line_json, cwd, file_path, remote_addr, remote_port, metadata_json
FROM events
ORDER BY timestamp ASC, event_id ASC
LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()

	var loaded []events.Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	return loaded, nil
}

func (store *SQLite) ListIncidents(ctx context.Context, limit int) ([]compress.Incident, error) {
	rows, err := store.db.QueryContext(ctx, `
SELECT incident_id, start_time, end_time, root_process_json, process_tree_json,
       risk_score, signals_json, timeline_json, summary, llm_status, dropped_events
FROM incidents
ORDER BY start_time DESC, incident_id ASC
LIMIT ?`, normalizeLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var loaded []compress.Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, incident)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	return loaded, nil
}

func (store *SQLite) GetIncident(ctx context.Context, incidentID string) (compress.Incident, []events.Event, error) {
	incident, err := scanIncident(store.db.QueryRowContext(ctx, `
SELECT incident_id, start_time, end_time, root_process_json, process_tree_json,
       risk_score, signals_json, timeline_json, summary, llm_status, dropped_events
FROM incidents
WHERE incident_id = ?`, incidentID))
	if err != nil {
		return compress.Incident{}, nil, err
	}

	rows, err := store.db.QueryContext(ctx, `
SELECT e.event_id, e.timestamp, e.host, e.container_id, e.container_name,
       e.pid, e.ppid, e.uid, e.process_name, e.parent_process_name,
       e.event_type, e.executable_path, e.command_line_json, e.cwd,
       e.file_path, e.remote_addr, e.remote_port, e.metadata_json
FROM events e
JOIN incident_events ie ON ie.event_id = e.event_id
WHERE ie.incident_id = ?
ORDER BY e.timestamp ASC, e.event_id ASC`, incidentID)
	if err != nil {
		return compress.Incident{}, nil, fmt.Errorf("list incident events %q: %w", incidentID, err)
	}
	defer rows.Close()

	var linkedEvents []events.Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return compress.Incident{}, nil, err
		}
		linkedEvents = append(linkedEvents, event)
	}
	if err := rows.Err(); err != nil {
		return compress.Incident{}, nil, fmt.Errorf("list incident events %q: %w", incidentID, err)
	}
	return incident, linkedEvents, nil
}

type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type scanner interface {
	Scan(dest ...any) error
}

func insertEvent(ctx context.Context, exec executor, event events.Event) error {
	commandLine, err := json.Marshal(event.CommandLine)
	if err != nil {
		return fmt.Errorf("encode command line: %w", err)
	}
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}

	_, err = exec.ExecContext(ctx, `
INSERT INTO events (
    event_id, timestamp, host, container_id, container_name, pid, ppid, uid,
    process_name, parent_process_name, event_type, executable_path,
    command_line_json, cwd, file_path, remote_addr, remote_port, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO UPDATE SET
    timestamp = excluded.timestamp,
    host = excluded.host,
    container_id = excluded.container_id,
    container_name = excluded.container_name,
    pid = excluded.pid,
    ppid = excluded.ppid,
    uid = excluded.uid,
    process_name = excluded.process_name,
    parent_process_name = excluded.parent_process_name,
    event_type = excluded.event_type,
    executable_path = excluded.executable_path,
    command_line_json = excluded.command_line_json,
    cwd = excluded.cwd,
    file_path = excluded.file_path,
    remote_addr = excluded.remote_addr,
    remote_port = excluded.remote_port,
    metadata_json = excluded.metadata_json`,
		event.EventID, formatTime(event.Timestamp), event.Host, event.ContainerID,
		event.ContainerName, event.PID, event.PPID, event.UID, event.ProcessName,
		event.ParentProcessName, event.EventType, event.ExecutablePath, commandLine,
		event.CWD, event.FilePath, event.RemoteAddr, event.RemotePort, metadata)
	return err
}

func insertIncident(ctx context.Context, exec executor, incident compress.Incident) error {
	rootProcess, err := json.Marshal(incident.RootProcess)
	if err != nil {
		return fmt.Errorf("encode root process: %w", err)
	}
	processTree, err := json.Marshal(incident.ProcessTree)
	if err != nil {
		return fmt.Errorf("encode process tree: %w", err)
	}
	signals, err := json.Marshal(incident.Signals)
	if err != nil {
		return fmt.Errorf("encode signals: %w", err)
	}
	timeline, err := json.Marshal(incident.Timeline)
	if err != nil {
		return fmt.Errorf("encode timeline: %w", err)
	}

	_, err = exec.ExecContext(ctx, `
INSERT INTO incidents (
    incident_id, start_time, end_time, root_process_json, process_tree_json,
    risk_score, signals_json, timeline_json, summary, llm_status, dropped_events
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(incident_id) DO UPDATE SET
    start_time = excluded.start_time,
    end_time = excluded.end_time,
    root_process_json = excluded.root_process_json,
    process_tree_json = excluded.process_tree_json,
    risk_score = excluded.risk_score,
    signals_json = excluded.signals_json,
    timeline_json = excluded.timeline_json,
    summary = excluded.summary,
    llm_status = excluded.llm_status,
    dropped_events = excluded.dropped_events`,
		incident.IncidentID, formatTime(incident.StartTime), formatTime(incident.EndTime),
		rootProcess, processTree, incident.RiskScore, signals, timeline,
		incident.Summary, incident.LLMStatus, incident.DroppedEvents)
	return err
}

func replaceIncidentEventLinks(ctx context.Context, exec executor, incidentID string, eventIDs []string) error {
	if incidentID == "" {
		return errors.New("incident ID is required")
	}
	if _, err := exec.ExecContext(ctx, "DELETE FROM incident_events WHERE incident_id = ?", incidentID); err != nil {
		return fmt.Errorf("clear incident event links %q: %w", incidentID, err)
	}
	for _, eventID := range eventIDs {
		if _, err := exec.ExecContext(ctx,
			"INSERT INTO incident_events (incident_id, event_id) VALUES (?, ?)",
			incidentID, eventID); err != nil {
			return fmt.Errorf("link incident %q to event %q: %w", incidentID, eventID, err)
		}
	}
	return nil
}

func scanEvent(row scanner) (events.Event, error) {
	var event events.Event
	var timestamp string
	var commandLine []byte
	var metadata []byte
	if err := row.Scan(
		&event.EventID, &timestamp, &event.Host, &event.ContainerID,
		&event.ContainerName, &event.PID, &event.PPID, &event.UID,
		&event.ProcessName, &event.ParentProcessName, &event.EventType,
		&event.ExecutablePath, &commandLine, &event.CWD, &event.FilePath,
		&event.RemoteAddr, &event.RemotePort, &metadata,
	); err != nil {
		return event, fmt.Errorf("scan event: %w", err)
	}
	var err error
	event.Timestamp, err = parseTime(timestamp)
	if err != nil {
		return event, fmt.Errorf("parse event %q timestamp: %w", event.EventID, err)
	}
	if err := json.Unmarshal(commandLine, &event.CommandLine); err != nil {
		return event, fmt.Errorf("decode event %q command line: %w", event.EventID, err)
	}
	if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
		return event, fmt.Errorf("decode event %q metadata: %w", event.EventID, err)
	}
	return event, nil
}

func scanIncident(row scanner) (compress.Incident, error) {
	var incident compress.Incident
	var startTime string
	var endTime string
	var rootProcess []byte
	var processTree []byte
	var signals []byte
	var timeline []byte
	if err := row.Scan(
		&incident.IncidentID, &startTime, &endTime, &rootProcess,
		&processTree, &incident.RiskScore, &signals, &timeline,
		&incident.Summary, &incident.LLMStatus, &incident.DroppedEvents,
	); err != nil {
		return incident, fmt.Errorf("scan incident: %w", err)
	}

	var err error
	incident.StartTime, err = parseTime(startTime)
	if err != nil {
		return incident, fmt.Errorf("parse incident %q start time: %w", incident.IncidentID, err)
	}
	incident.EndTime, err = parseTime(endTime)
	if err != nil {
		return incident, fmt.Errorf("parse incident %q end time: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(rootProcess, &incident.RootProcess); err != nil {
		return incident, fmt.Errorf("decode incident %q root process: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(processTree, &incident.ProcessTree); err != nil {
		return incident, fmt.Errorf("decode incident %q process tree: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(signals, &incident.Signals); err != nil {
		return incident, fmt.Errorf("decode incident %q signals: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(timeline, &incident.Timeline); err != nil {
		return incident, fmt.Errorf("decode incident %q timeline: %w", incident.IncidentID, err)
	}
	return incident, nil
}

func validateIncident(incident compress.Incident) error {
	switch {
	case incident.IncidentID == "":
		return errors.New("incident_id is required")
	case incident.StartTime.IsZero():
		return errors.New("start_time is required")
	case incident.EndTime.IsZero():
		return errors.New("end_time is required")
	case incident.LLMStatus == "":
		return errors.New("llm_status is required")
	default:
		return nil
	}
}

func formatTime(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func parseTime(timestamp string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, timestamp)
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultLimit
	}
	return limit
}
