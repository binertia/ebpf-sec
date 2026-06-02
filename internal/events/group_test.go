package events_test

import (
	"os"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestTreeGrouperSeparatesUnrelatedProcesses(t *testing.T) {
	fixture, err := os.Open("../../testdata/events/mixed-process-trees.json")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	normalizedEvents, err := events.LoadJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}

	groups := events.NewTreeGrouper(events.DefaultCorrelationWindow).Group(normalizedEvents)
	if len(groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(groups))
	}
	assertEventIDs(t, groups[0].Events, []string{"evt-001", "evt-002", "evt-003", "evt-004", "evt-005"})
	assertEventIDs(t, groups[1].Events, []string{"evt-noise-001", "evt-noise-002"})
}

func TestTreeGrouperBoundsCorrelationWindow(t *testing.T) {
	start := time.Date(2026, time.June, 2, 10, 15, 0, 0, time.UTC)
	normalizedEvents := []events.Event{
		testEvent("evt-early", start, 100, 1),
		testEvent("evt-late", start.Add(events.DefaultCorrelationWindow+time.Second), 100, 1),
	}

	groups := events.NewTreeGrouper(events.DefaultCorrelationWindow).Group(normalizedEvents)
	if len(groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(groups))
	}
}

func TestTreeGrouperCorrelatesWrittenArtifactExecution(t *testing.T) {
	start := time.Date(2026, time.June, 2, 10, 15, 0, 0, time.UTC)
	normalizedEvents := []events.Event{
		{
			EventID:     "evt-write",
			Timestamp:   start,
			Host:        "devbox-01",
			PID:         100,
			ProcessName: "writer",
			EventType:   events.TypeFileWrite,
			FilePath:    "/tmp/payload",
		},
		{
			EventID:        "evt-exec",
			Timestamp:      start.Add(time.Second),
			Host:           "devbox-01",
			PID:            200,
			PPID:           1,
			ProcessName:    "payload",
			EventType:      events.TypeExecve,
			ExecutablePath: "/tmp/payload",
		},
	}

	groups := events.NewTreeGrouper(events.DefaultCorrelationWindow).Group(normalizedEvents)
	if len(groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(groups))
	}
	assertEventIDs(t, groups[0].Events, []string{"evt-write", "evt-exec"})
}

func testEvent(eventID string, timestamp time.Time, pid, ppid int) events.Event {
	return events.Event{
		EventID:     eventID,
		Timestamp:   timestamp,
		Host:        "devbox-01",
		PID:         pid,
		PPID:        ppid,
		ProcessName: "process",
		EventType:   events.TypeExecve,
	}
}

func assertEventIDs(t *testing.T, actual []events.Event, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("event count = %d, want %d", len(actual), len(expected))
	}
	for index, event := range actual {
		if event.EventID != expected[index] {
			t.Fatalf("event %d ID = %q, want %q", index, event.EventID, expected[index])
		}
	}
}
