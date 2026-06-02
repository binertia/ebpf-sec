package persistqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"runtime-guard/internal/events"
)

const DefaultCapacity = 1024

type EventSaver interface {
	SaveEvent(context.Context, events.Event) error
}

type Stats struct {
	Received  uint64
	Enqueued  uint64
	Persisted uint64
	Dropped   uint64
}

type Queue struct {
	saver  EventSaver
	events chan events.Event
	done   chan struct{}
	errCh  chan error

	mu     sync.Mutex
	closed bool
	err    error

	received  uint64
	enqueued  uint64
	persisted uint64
	dropped   uint64
}

func New(saver EventSaver, capacity int) (*Queue, error) {
	if saver == nil {
		return nil, errors.New("event saver is required")
	}
	if capacity <= 0 {
		capacity = DefaultCapacity
	}

	queue := &Queue{
		saver:  saver,
		events: make(chan events.Event, capacity),
		done:   make(chan struct{}),
		errCh:  make(chan error, 1),
	}
	go queue.run()
	return queue, nil
}

func (queue *Queue) Enqueue(event events.Event) bool {
	queue.mu.Lock()
	defer queue.mu.Unlock()

	if queue.closed {
		atomic.AddUint64(&queue.received, 1)
		atomic.AddUint64(&queue.dropped, 1)
		return false
	}

	atomic.AddUint64(&queue.received, 1)
	select {
	case queue.events <- event:
		atomic.AddUint64(&queue.enqueued, 1)
		return true
	default:
		atomic.AddUint64(&queue.dropped, 1)
		return false
	}
}

func (queue *Queue) Close() error {
	queue.mu.Lock()
	if !queue.closed {
		queue.closed = true
		close(queue.events)
	}
	queue.mu.Unlock()

	<-queue.done
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.err
}

func (queue *Queue) Errors() <-chan error {
	return queue.errCh
}

func (queue *Queue) Stats() Stats {
	return Stats{
		Received:  atomic.LoadUint64(&queue.received),
		Enqueued:  atomic.LoadUint64(&queue.enqueued),
		Persisted: atomic.LoadUint64(&queue.persisted),
		Dropped:   atomic.LoadUint64(&queue.dropped),
	}
}

func (queue *Queue) run() {
	defer close(queue.done)

	for event := range queue.events {
		if err := queue.saver.SaveEvent(context.Background(), event); err != nil {
			queue.mu.Lock()
			if queue.err == nil {
				queue.err = fmt.Errorf("save event %q: %w", event.EventID, err)
				select {
				case queue.errCh <- queue.err:
				default:
				}
			}
			queue.mu.Unlock()
			return
		}
		atomic.AddUint64(&queue.persisted, 1)
	}
}
