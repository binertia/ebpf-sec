package pipeline

import (
	"fmt"
	"time"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/detect"
	"tracejutsu/internal/events"
)

const (
	DefaultInactivityTimeout = 15 * time.Second
	DefaultMaxCandidates     = 4096
	DefaultMaxEvents         = events.DefaultMaxEventsPerCandidate
	DefaultMaxRetainedEvents = events.DefaultMaxRetainedEvents
)

type Config struct {
	CorrelationWindow time.Duration
	InactivityTimeout time.Duration
	MaxCandidates     int
	MaxEvents         int
	MaxRetainedEvents int
}

type Analysis struct {
	Incident compress.Incident
	Events   []events.Event
}

type Stats struct {
	GroupedCandidates  uint64
	AnalyzedCandidates uint64
	Incidents          uint64
}

type Processor struct {
	grouper    *events.StreamGrouper
	detector   detect.Detector
	compressor compress.Compressor
	stats      Stats
}

func New(config Config, detector detect.Detector, compressor compress.Compressor) *Processor {
	if config.CorrelationWindow <= 0 {
		config.CorrelationWindow = events.DefaultCorrelationWindow
	}
	if config.InactivityTimeout <= 0 {
		config.InactivityTimeout = DefaultInactivityTimeout
	}
	if config.MaxCandidates <= 0 {
		config.MaxCandidates = DefaultMaxCandidates
	}
	if config.MaxEvents <= 0 {
		config.MaxEvents = DefaultMaxEvents
	}
	if config.MaxRetainedEvents <= 0 {
		config.MaxRetainedEvents = DefaultMaxRetainedEvents
	}
	return &Processor{
		grouper: events.NewStreamGrouper(events.StreamGrouperConfig{
			CorrelationWindow: config.CorrelationWindow,
			InactivityTimeout: config.InactivityTimeout,
			MaxCandidates:     config.MaxCandidates,
			MaxEvents:         config.MaxEvents,
			MaxRetainedEvents: config.MaxRetainedEvents,
		}),
		detector:   detector,
		compressor: compressor,
	}
}

func (processor *Processor) Add(event events.Event) ([]Analysis, error) {
	return processor.analyze(processor.grouper.Add(event))
}

func (processor *Processor) FlushInactive(now time.Time) ([]Analysis, error) {
	return processor.analyze(processor.grouper.FlushInactive(now))
}

func (processor *Processor) Drain() ([]Analysis, error) {
	return processor.analyze(processor.grouper.Drain())
}

func (processor *Processor) ActiveCandidates() int {
	return processor.grouper.ActiveCandidates()
}

func (processor *Processor) Stats() Stats {
	return processor.stats
}

func (processor *Processor) analyze(groups []events.Group) ([]Analysis, error) {
	var analyses []Analysis
	processor.stats.GroupedCandidates += uint64(len(groups))
	for _, group := range groups {
		processor.stats.AnalyzedCandidates++
		detection := processor.detector.Analyze(group.Events)
		if len(detection.Signals) == 0 {
			continue
		}
		incident, err := processor.compressor.Compress(group.Events, detection)
		if err != nil {
			return nil, fmt.Errorf("compress incident candidate: %w", err)
		}
		incident.DroppedEvents = group.DroppedEvents
		analyses = append(analyses, Analysis{
			Incident: incident,
			Events:   group.Events,
		})
		processor.stats.Incidents++
	}
	return analyses, nil
}
