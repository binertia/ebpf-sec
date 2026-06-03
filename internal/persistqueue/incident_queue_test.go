package persistqueue

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/events"
)

type blockingIncidentSaver struct {
	started   chan struct{}
	release   chan struct{}
	mu        sync.Mutex
	incidents []string
	events    []string
	commands  [][]string
	metadata  []map[string]any
	trees     [][]string
}

func (s *blockingIncidentSaver) SaveIncidentWithEvents(_ context.Context, incident compress.Incident, normalizedEvents []events.Event) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release

	eventIDs := make([]string, 0, len(normalizedEvents))
	for _, event := range normalizedEvents {
		eventIDs = append(eventIDs, event.EventID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents = append(s.incidents, incident.IncidentID)
	s.events = append(s.events, eventIDs...)
	for _, event := range normalizedEvents {
		s.commands = append(s.commands, append([]string(nil), event.CommandLine...))
		s.metadata = append(s.metadata, cloneMap(event.Metadata))
	}
	s.trees = append(s.trees, append([]string(nil), incident.ProcessTree...))
	return nil
}

type incidentErrorSaver struct{}

func (incidentErrorSaver) SaveIncidentWithEvents(context.Context, compress.Incident, []events.Event) error {
	return errors.New("boom")
}

type incidentContextBlockingSaver struct {
	started chan struct{}
}

func (s incidentContextBlockingSaver) SaveIncidentWithEvents(ctx context.Context, _ compress.Incident, _ []events.Event) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestIncidentQueueCloseFlushesPendingIncidents(t *testing.T) {
	saver := &blockingIncidentSaver{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	queue, err := NewIncidentQueue(saver, 4)
	if err != nil {
		t.Fatal(err)
	}

	for _, incidentID := range []string{"inc-1", "inc-2"} {
		if !queue.Enqueue(IncidentRecord{Incident: compress.Incident{IncidentID: incidentID}}) {
			t.Fatalf("enqueue %q dropped unexpectedly", incidentID)
		}
	}
	select {
	case <-saver.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	close(saver.release)
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	saver.mu.Lock()
	defer saver.mu.Unlock()
	if len(saver.incidents) != 2 {
		t.Fatalf("persisted incidents = %d, want 2", len(saver.incidents))
	}
	stats := queue.Stats()
	if stats.Persisted != 2 || stats.Dropped != 0 {
		t.Fatalf("stats = %#v, want persisted=2 dropped=0", stats)
	}
}

func TestIncidentQueueDropsWhenCapacityIsExceeded(t *testing.T) {
	saver := &blockingIncidentSaver{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	queue, err := NewIncidentQueue(saver, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(saver.release)
		if closeErr := queue.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}()

	if !queue.Enqueue(IncidentRecord{Incident: compress.Incident{IncidentID: "inc-1"}}) {
		t.Fatal("first enqueue dropped unexpectedly")
	}
	select {
	case <-saver.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	if !queue.Enqueue(IncidentRecord{Incident: compress.Incident{IncidentID: "inc-2"}}) {
		t.Fatal("second enqueue dropped unexpectedly")
	}
	if queue.Enqueue(IncidentRecord{Incident: compress.Incident{IncidentID: "inc-3"}}) {
		t.Fatal("third enqueue should have been dropped")
	}

	stats := queue.Stats()
	if stats.Received != 3 || stats.Enqueued != 2 || stats.Dropped != 1 {
		t.Fatalf("stats = %#v, want received=3 enqueued=2 dropped=1", stats)
	}
}

func TestIncidentQueueReportsSaverError(t *testing.T) {
	queue, err := NewIncidentQueue(incidentErrorSaver{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !queue.Enqueue(IncidentRecord{Incident: compress.Incident{IncidentID: "inc-1"}}) {
		t.Fatal("enqueue dropped unexpectedly")
	}

	select {
	case got := <-queue.Errors():
		if got == nil {
			t.Fatal("error channel yielded nil")
		}
	case <-time.After(time.Second):
		t.Fatal("expected saver error")
	}

	if queue.Enqueue(IncidentRecord{Incident: compress.Incident{IncidentID: "inc-after-error"}}) {
		t.Fatal("enqueue after saver error should have been dropped")
	}

	if err := queue.Close(); err == nil {
		t.Fatal("close should report saver error")
	}
	if stats := queue.Stats(); stats.Dropped != 2 {
		t.Fatalf("stats = %#v, want dropped=2 for failed incident and post-error enqueue", stats)
	}
}

func TestIncidentQueueSaveTimeoutUnblocksClose(t *testing.T) {
	saver := incidentContextBlockingSaver{started: make(chan struct{}, 1)}
	queue, err := NewIncidentQueueWithConfig(saver, Config{
		Capacity:    1,
		SaveTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !queue.Enqueue(IncidentRecord{Incident: compress.Incident{IncidentID: "inc-timeout"}}) {
		t.Fatal("enqueue dropped unexpectedly")
	}

	select {
	case <-saver.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	started := time.Now()
	err = queue.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("close took %s, want bounded timeout", elapsed)
	}
	stats := queue.Stats()
	if stats.Persisted != 0 || stats.Dropped != 1 {
		t.Fatalf("stats = %#v, want persisted=0 dropped=1", stats)
	}
}

func TestIncidentQueueCopiesQueuedRecords(t *testing.T) {
	saver := &blockingIncidentSaver{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	queue, err := NewIncidentQueue(saver, 1)
	if err != nil {
		t.Fatal(err)
	}

	record := IncidentRecord{
		Incident: compress.Incident{
			IncidentID:  "inc-original",
			ProcessTree: []string{"original-tree"},
		},
		Events: []events.Event{{
			EventID:     "evt-original",
			CommandLine: []string{"cmd", "original"},
			Metadata: map[string]any{
				"value":  "original",
				"nested": map[string]any{"inner": "original"},
			},
		}},
	}
	if !queue.Enqueue(record) {
		t.Fatal("enqueue dropped unexpectedly")
	}
	select {
	case <-saver.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	record.Incident.ProcessTree[0] = "mutated-tree"
	record.Events[0].EventID = "evt-mutated"
	record.Events[0].CommandLine[1] = "mutated"
	record.Events[0].Metadata["value"] = "mutated"
	record.Events[0].Metadata["nested"].(map[string]any)["inner"] = "mutated"
	close(saver.release)

	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	saver.mu.Lock()
	defer saver.mu.Unlock()
	if len(saver.events) != 1 || saver.events[0] != "evt-original" {
		t.Fatalf("persisted events = %#v, want evt-original", saver.events)
	}
	if len(saver.commands) != 1 || len(saver.commands[0]) != 2 || saver.commands[0][1] != "original" {
		t.Fatalf("persisted command line = %#v, want original", saver.commands)
	}
	if len(saver.metadata) != 1 || saver.metadata[0]["value"] != "original" {
		t.Fatalf("persisted metadata = %#v, want original", saver.metadata)
	}
	nested, ok := saver.metadata[0]["nested"].(map[string]any)
	if !ok || nested["inner"] != "original" {
		t.Fatalf("persisted nested metadata = %#v, want original", saver.metadata)
	}
	if len(saver.trees) != 1 || len(saver.trees[0]) != 1 || saver.trees[0][0] != "original-tree" {
		t.Fatalf("persisted process tree = %#v, want original-tree", saver.trees)
	}
}
