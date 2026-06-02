package store

import (
	"context"
	"database/sql"
	"fmt"
)

func ensureIncidentDroppedEventsColumn(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(incidents)")
	if err != nil {
		return fmt.Errorf("inspect incidents schema: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var columnID int
		var name string
		var columnType string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("inspect incidents schema: %w", err)
		}
		if name == "dropped_events" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect incidents schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close incidents schema rows: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		"ALTER TABLE incidents ADD COLUMN dropped_events INTEGER NOT NULL DEFAULT 0"); err != nil {
		return fmt.Errorf("add incidents dropped_events column: %w", err)
	}
	return nil
}
