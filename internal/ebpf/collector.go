// Package ebpf defines the collector boundary. Kernel probe loading is added
// only after the fake-event pipeline is stable.
package ebpf

import (
	"context"
	"errors"

	"runtime-guard/internal/events"
)

type Collector interface {
	Run(ctx context.Context, sink chan<- events.Event) error
}

type Stats struct {
	RingBufferDropped  uint64
	CorrelationDropped uint64
}

type StatsProvider interface {
	Stats() Stats
}

type CompositeCollector struct {
	collectors []Collector
}

func NewCompositeCollector(collectors ...Collector) *CompositeCollector {
	return &CompositeCollector{collectors: collectors}
}

func (collector *CompositeCollector) Stats() Stats {
	var combined Stats
	for _, child := range collector.collectors {
		if provider, ok := child.(StatsProvider); ok {
			stats := provider.Stats()
			combined.RingBufferDropped += stats.RingBufferDropped
			combined.CorrelationDropped += stats.CorrelationDropped
		}
	}
	return combined
}

func (collector *CompositeCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	if len(collector.collectors) == 0 {
		return errors.New("at least one collector is required")
	}

	runContext, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan error, len(collector.collectors))
	for _, child := range collector.collectors {
		go func() {
			results <- child.Run(runContext, sink)
		}()
	}

	var firstError error
	for index := range collector.collectors {
		if err := <-results; err != nil && firstError == nil {
			firstError = err
		}
		if index == 0 {
			cancel()
		}
	}
	return firstError
}
