package store

const schema = `
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    host TEXT NOT NULL,
    container_id TEXT NOT NULL DEFAULT '',
    container_name TEXT NOT NULL DEFAULT '',
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    parent_process_name TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    executable_path TEXT NOT NULL DEFAULT '',
    command_line_json TEXT NOT NULL DEFAULT '[]',
    cwd TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    remote_addr TEXT NOT NULL DEFAULT '',
    remote_port INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS events_timestamp_idx
    ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_process_idx
    ON events(host, container_id, pid, timestamp);
CREATE INDEX IF NOT EXISTS events_file_path_idx
    ON events(file_path, timestamp);
CREATE INDEX IF NOT EXISTS events_type_process_idx
    ON events(event_type, process_name, executable_path);
CREATE INDEX IF NOT EXISTS events_type_file_path_idx
    ON events(event_type, file_path);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    root_process_json TEXT NOT NULL,
    process_tree_json TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    signals_json TEXT NOT NULL,
    timeline_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    llm_status TEXT NOT NULL,
    dropped_events INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS incidents_start_time_idx
    ON incidents(start_time);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE IF NOT EXISTS llm_reports (
    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    model TEXT NOT NULL,
    report_json TEXT NOT NULL,
    raw_response TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    score_impact INTEGER NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
`
