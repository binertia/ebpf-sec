package events_test

import (
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestStreamGrouperFlushesInactiveCandidate(t *testing.T) {
	start := time.Date(2026, time.June, 2, 10, 15, 0, 0, time.UTC)
	grouper := events.NewStreamGrouper(events.StreamGrouperConfig{
		CorrelationWindow: time.Minute,
		InactivityTimeout: 10 * time.Second,
	})
	grouper.Add(testEvent("evt-001", start, 100, 1))

	groups := grouper.FlushInactive(start.Add(10 * time.Second))
	if len(groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(groups))
	}
	assertEventIDs(t, groups[0].Events, []string{"evt-001"})
	if grouper.ActiveCandidates() != 0 {
		t.Fatalf("active candidates = %d, want 0", grouper.ActiveCandidates())
	}
}

func TestStreamGrouperEvictsOldestCandidateAtCapacity(t *testing.T) {
	start := time.Date(2026, time.June, 2, 10, 15, 0, 0, time.UTC)
	grouper := events.NewStreamGrouper(events.StreamGrouperConfig{
		CorrelationWindow: time.Minute,
		InactivityTimeout: time.Minute,
		MaxCandidates:     1,
	})
	grouper.Add(testEvent("evt-oldest", start, 100, 1))

	groups := grouper.Add(testEvent("evt-new", start.Add(time.Second), 200, 1))
	if len(groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(groups))
	}
	assertEventIDs(t, groups[0].Events, []string{"evt-oldest"})
	if grouper.ActiveCandidates() != 1 {
		t.Fatalf("active candidates = %d, want 1", grouper.ActiveCandidates())
	}
}

func TestStreamGrouperBoundsEventsPerCandidate(t *testing.T) {
	start := time.Date(2026, time.June, 2, 10, 15, 0, 0, time.UTC)
	grouper := events.NewStreamGrouper(events.StreamGrouperConfig{
		CorrelationWindow: time.Minute,
		InactivityTimeout: time.Minute,
		MaxEvents:         2,
	})
	grouper.Add(testEvent("evt-001", start, 100, 1))
	grouper.Add(testEvent("evt-002", start.Add(time.Second), 100, 1))
	grouper.Add(testEvent("evt-003", start.Add(2*time.Second), 100, 1))

	groups := grouper.Drain()
	if len(groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(groups))
	}
	assertEventIDs(t, groups[0].Events, []string{"evt-002", "evt-003"})
	if groups[0].DroppedEvents != 1 {
		t.Fatalf("dropped events = %d, want 1", groups[0].DroppedEvents)
	}
}

func TestStreamGrouperBoundsTotalRetainedEvents(t *testing.T) {
	start := time.Date(2026, time.June, 2, 10, 15, 0, 0, time.UTC)
	grouper := events.NewStreamGrouper(events.StreamGrouperConfig{
		CorrelationWindow: time.Minute,
		InactivityTimeout: time.Minute,
		MaxCandidates:     3,
		MaxEvents:         2,
		MaxRetainedEvents: 2,
	})
	grouper.Add(testEvent("evt-001", start, 100, 1))
	grouper.Add(testEvent("evt-002", start.Add(time.Second), 200, 1))

	groups := grouper.Add(testEvent("evt-003", start.Add(2*time.Second), 300, 1))
	if len(groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(groups))
	}
	assertEventIDs(t, groups[0].Events, []string{"evt-001"})
	if grouper.ActiveCandidates() != 2 {
		t.Fatalf("active candidates = %d, want 2", grouper.ActiveCandidates())
	}
}
