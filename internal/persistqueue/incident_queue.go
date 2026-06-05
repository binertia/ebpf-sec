package persistqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/events"
)

const DefaultIncidentCapacity = 256

type IncidentSaver interface {
	SaveIncidentWithEvents(context.Context, compress.Incident, []events.Event) error
}

type IncidentRecord struct {
	Incident compress.Incident
	Events   []events.Event
}

type IncidentQueue struct {
	saver       IncidentSaver
	saveTimeout time.Duration
	incidents   chan IncidentRecord
	done        chan struct{}
	errCh       chan error

	mu     sync.Mutex
	closed bool
	err    error

	received  uint64
	enqueued  uint64
	persisted uint64
	dropped   uint64
}

func NewIncidentQueue(saver IncidentSaver, capacity int) (*IncidentQueue, error) {
	return NewIncidentQueueWithConfig(saver, Config{Capacity: capacity})
}

func NewIncidentQueueWithConfig(saver IncidentSaver, config Config) (*IncidentQueue, error) {
	if saver == nil {
		return nil, errors.New("incident saver is required")
	}
	if config.Capacity <= 0 {
		config.Capacity = DefaultIncidentCapacity
	}
	if config.SaveTimeout < 0 {
		return nil, errors.New("save timeout must be zero or positive")
	}
	if config.SaveTimeout == 0 {
		config.SaveTimeout = DefaultSaveTimeout
	}

	queue := &IncidentQueue{
		saver:       saver,
		saveTimeout: config.SaveTimeout,
		incidents:   make(chan IncidentRecord, config.Capacity),
		done:        make(chan struct{}),
		errCh:       make(chan error, 1),
	}
	go queue.run()
	return queue, nil
}

func (queue *IncidentQueue) Enqueue(record IncidentRecord) bool {
	queue.mu.Lock()
	defer queue.mu.Unlock()

	if queue.closed {
		atomic.AddUint64(&queue.received, 1)
		atomic.AddUint64(&queue.dropped, 1)
		return false
	}

	atomic.AddUint64(&queue.received, 1)
	select {
	case queue.incidents <- cloneIncidentRecord(record):
		atomic.AddUint64(&queue.enqueued, 1)
		return true
	default:
		atomic.AddUint64(&queue.dropped, 1)
		return false
	}
}

func (queue *IncidentQueue) Close() error {
	queue.mu.Lock()
	if !queue.closed {
		queue.closed = true
		close(queue.incidents)
	}
	queue.mu.Unlock()

	<-queue.done
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.err
}

func (queue *IncidentQueue) Errors() <-chan error {
	return queue.errCh
}

func (queue *IncidentQueue) Stats() Stats {
	return Stats{
		Received:  atomic.LoadUint64(&queue.received),
		Enqueued:  atomic.LoadUint64(&queue.enqueued),
		Persisted: atomic.LoadUint64(&queue.persisted),
		Dropped:   atomic.LoadUint64(&queue.dropped),
	}
}

func (queue *IncidentQueue) run() {
	defer close(queue.done)

	for incident := range queue.incidents {
		if err := queue.saveIncident(incident); err != nil {
			queue.recordError(1, describeIncidentError(incident, err))
			return
		}
		atomic.AddUint64(&queue.persisted, 1)
	}
}

func (queue *IncidentQueue) recordError(failedIncidents int, err error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.err != nil {
		return
	}
	queue.err = err
	atomic.AddUint64(&queue.dropped, uint64(failedIncidents+len(queue.incidents)))
	if !queue.closed {
		queue.closed = true
		close(queue.incidents)
	}
	select {
	case queue.errCh <- queue.err:
	default:
	}
}

func (queue *IncidentQueue) saveIncident(record IncidentRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), queue.saveTimeout)
	defer cancel()
	return queue.saver.SaveIncidentWithEvents(ctx, record.Incident, record.Events)
}

func describeIncidentError(record IncidentRecord, err error) error {
	return fmt.Errorf("save incident %q: %w", record.Incident.IncidentID, err)
}

func cloneIncidentRecord(record IncidentRecord) IncidentRecord {
	record.Incident = cloneIncident(record.Incident)
	record.Events = cloneEvents(record.Events)
	return record
}

func cloneIncident(incident compress.Incident) compress.Incident {
	incident.ProcessTree = append([]string(nil), incident.ProcessTree...)
	incident.Signals = append([]string(nil), incident.Signals...)
	incident.Timeline = append([]string(nil), incident.Timeline...)
	return incident
}

func cloneEvents(input []events.Event) []events.Event {
	if input == nil {
		return nil
	}
	cloned := make([]events.Event, len(input))
	for index, event := range input {
		event.CommandLine = append([]string(nil), event.CommandLine...)
		if event.Metadata != nil {
			event.Metadata = cloneMap(event.Metadata)
		}
		cloned[index] = event
	}
	return cloned
}

func cloneMap(input map[string]any) map[string]any {
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = cloneValue(value)
	}
	return cloned
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		cloned := make([]any, len(typed))
		for index, entry := range typed {
			cloned[index] = cloneValue(entry)
		}
		return cloned
	case map[string]any:
		return cloneMap(typed)
	default:
		return value
	}
}
