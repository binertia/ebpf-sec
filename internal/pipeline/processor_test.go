package pipeline_test

import (
	"os"
	"testing"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/detect"
	"runtime-guard/internal/events"
	"runtime-guard/internal/pipeline"
)

func TestProcessorFlushesSuspiciousInactiveCandidate(t *testing.T) {
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")
	processor := newProcessor()
	for _, event := range normalizedEvents {
		analyses, err := processor.Add(event)
		if err != nil {
			t.Fatal(err)
		}
		if len(analyses) != 0 {
			t.Fatalf("unexpected early incident count = %d", len(analyses))
		}
	}

	analyses, err := processor.FlushInactive(normalizedEvents[len(normalizedEvents)-1].Timestamp.Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	assertSuspiciousAnalysis(t, analyses)
}

func TestProcessorSuppressesBenignCandidate(t *testing.T) {
	processor := newProcessor()
	start := time.Date(2026, time.June, 2, 10, 15, 0, 0, time.UTC)
	_, err := processor.Add(events.Event{
		EventID:     "evt-benign",
		Timestamp:   start,
		Host:        "devbox-01",
		PID:         100,
		PPID:        1,
		ProcessName: "true",
		EventType:   events.TypeExecve,
	})
	if err != nil {
		t.Fatal(err)
	}

	analyses, err := processor.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 0 {
		t.Fatalf("analysis count = %d, want 0", len(analyses))
	}
	stats := processor.Stats()
	if stats.GroupedCandidates != 1 || stats.AnalyzedCandidates != 1 || stats.Incidents != 0 {
		t.Fatalf("stats = %#v, want grouped=1 analyzed=1 incidents=0", stats)
	}
}

func TestProcessorKeepsUnrelatedEventsOutOfIncident(t *testing.T) {
	normalizedEvents := loadFixture(t, "../../testdata/events/mixed-process-trees.json")
	processor := newProcessor()
	for _, event := range normalizedEvents {
		if _, err := processor.Add(event); err != nil {
			t.Fatal(err)
		}
	}

	analyses, err := processor.Drain()
	if err != nil {
		t.Fatal(err)
	}
	assertSuspiciousAnalysis(t, analyses)
	if len(analyses[0].Events) != 5 {
		t.Fatalf("incident event count = %d, want 5", len(analyses[0].Events))
	}
}

func TestProcessorDrainFlushesActiveCandidate(t *testing.T) {
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")
	processor := newProcessor()
	for _, event := range normalizedEvents {
		if _, err := processor.Add(event); err != nil {
			t.Fatal(err)
		}
	}

	analyses, err := processor.Drain()
	if err != nil {
		t.Fatal(err)
	}
	assertSuspiciousAnalysis(t, analyses)
	if processor.ActiveCandidates() != 0 {
		t.Fatalf("active candidates = %d, want 0", processor.ActiveCandidates())
	}
}

func TestProcessorReportsDroppedEventsWhenCandidateHistoryIsCapped(t *testing.T) {
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")
	root := events.Event{
		EventID:     "evt-root",
		Timestamp:   normalizedEvents[0].Timestamp.Add(-time.Second),
		Host:        normalizedEvents[0].Host,
		ContainerID: normalizedEvents[0].ContainerID,
		PID:         normalizedEvents[0].PPID,
		PPID:        1,
		ProcessName: "nginx",
		EventType:   events.TypeExecve,
	}

	processor := pipeline.New(pipeline.Config{
		CorrelationWindow: time.Minute,
		InactivityTimeout: 5 * time.Second,
		MaxCandidates:     32,
		MaxEvents:         len(normalizedEvents),
	}, detect.NewBasic(), compress.NewBasic())
	if _, err := processor.Add(root); err != nil {
		t.Fatal(err)
	}
	for _, event := range normalizedEvents {
		if _, err := processor.Add(event); err != nil {
			t.Fatal(err)
		}
	}

	analyses, err := processor.Drain()
	if err != nil {
		t.Fatal(err)
	}
	assertSuspiciousAnalysis(t, analyses)
	if analyses[0].Incident.DroppedEvents != 1 {
		t.Fatalf("dropped events = %d, want 1", analyses[0].Incident.DroppedEvents)
	}
}

func newProcessor() *pipeline.Processor {
	return pipeline.New(pipeline.Config{
		CorrelationWindow: time.Minute,
		InactivityTimeout: 5 * time.Second,
		MaxCandidates:     32,
	}, detect.NewBasic(), compress.NewBasic())
}

func loadFixture(t *testing.T, path string) []events.Event {
	t.Helper()
	fixture, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	normalizedEvents, err := events.LoadJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return normalizedEvents
}

func assertSuspiciousAnalysis(t *testing.T, analyses []pipeline.Analysis) {
	t.Helper()
	if len(analyses) != 1 {
		t.Fatalf("analysis count = %d, want 1", len(analyses))
	}
	if analyses[0].Incident.RiskScore != 100 {
		t.Fatalf("risk score = %d, want 100", analyses[0].Incident.RiskScore)
	}
}
