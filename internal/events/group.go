package events

import (
	"sort"
	"time"
)

const (
	DefaultCorrelationWindow     = 2 * time.Minute
	DefaultMaxEventsPerCandidate = 4096
	DefaultMaxRetainedEvents     = 65536
)

type Group struct {
	Events        []Event
	DroppedEvents int
}

type Grouper interface {
	Group(normalizedEvents []Event) []Group
}

type TreeGrouper struct {
	CorrelationWindow time.Duration
}

type StreamGrouperConfig struct {
	CorrelationWindow time.Duration
	InactivityTimeout time.Duration
	MaxCandidates     int
	MaxEvents         int
	MaxRetainedEvents int
}

type StreamGrouper struct {
	config     StreamGrouperConfig
	candidates []*candidate
	retained   int
}

func NewTreeGrouper(correlationWindow time.Duration) TreeGrouper {
	if correlationWindow <= 0 {
		correlationWindow = DefaultCorrelationWindow
	}
	return TreeGrouper{CorrelationWindow: correlationWindow}
}

func NewStreamGrouper(config StreamGrouperConfig) *StreamGrouper {
	if config.CorrelationWindow <= 0 {
		config.CorrelationWindow = DefaultCorrelationWindow
	}
	if config.InactivityTimeout <= 0 {
		config.InactivityTimeout = config.CorrelationWindow
	}
	if config.MaxCandidates <= 0 {
		config.MaxCandidates = 4096
	}
	if config.MaxEvents <= 0 {
		config.MaxEvents = DefaultMaxEventsPerCandidate
	}
	if config.MaxRetainedEvents <= 0 {
		config.MaxRetainedEvents = DefaultMaxRetainedEvents
	}
	if config.MaxEvents > config.MaxRetainedEvents {
		config.MaxEvents = config.MaxRetainedEvents
	}
	return &StreamGrouper{config: config}
}

// Group correlates events by workload, observed process ancestry, and shared
// written artifacts. The fixed window prevents long-running processes and PID
// reuse from creating unbounded incident candidates.
func (grouper TreeGrouper) Group(normalizedEvents []Event) []Group {
	ordered := append([]Event(nil), normalizedEvents...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].Timestamp.Before(ordered[right].Timestamp)
	})

	var candidates []*candidate
	for _, event := range ordered {
		candidateIndex := -1
		for index := len(candidates) - 1; index >= 0; index-- {
			if candidates[index].related(event, grouper.CorrelationWindow) {
				candidateIndex = index
				break
			}
		}

		if candidateIndex == -1 {
			candidates = append(candidates, newCandidate(event, 0))
			continue
		}
		candidates[candidateIndex].add(event)
	}

	groups := make([]Group, 0, len(candidates))
	for _, candidate := range candidates {
		groups = append(groups, candidate.group())
	}
	return groups
}

// Add correlates one event and returns candidates evicted by age or capacity.
func (grouper *StreamGrouper) Add(event Event) []Group {
	flushed := grouper.FlushInactive(event.Timestamp)
	for index := len(grouper.candidates) - 1; index >= 0; index-- {
		if grouper.candidates[index].related(event, grouper.config.CorrelationWindow) {
			before := len(grouper.candidates[index].events)
			grouper.candidates[index].add(event)
			grouper.retained += len(grouper.candidates[index].events) - before
			for grouper.retained > grouper.config.MaxRetainedEvents {
				flushed = append(flushed, grouper.flushOldest())
			}
			return flushed
		}
	}

	if len(grouper.candidates) >= grouper.config.MaxCandidates {
		flushed = append(flushed, grouper.flushOldest())
	}
	created := newCandidate(event, grouper.config.MaxEvents)
	grouper.candidates = append(grouper.candidates, created)
	grouper.retained += len(created.events)
	for grouper.retained > grouper.config.MaxRetainedEvents {
		flushed = append(flushed, grouper.flushOldest())
	}
	return flushed
}

// FlushInactive returns candidates that have gone quiet or reached the hard
// correlation-window limit.
func (grouper *StreamGrouper) FlushInactive(now time.Time) []Group {
	var flushed []Group
	active := grouper.candidates[:0]
	for _, candidate := range grouper.candidates {
		inactive := now.Sub(candidate.lastSeen) >= grouper.config.InactivityTimeout
		expired := now.Sub(candidate.startTime) >= grouper.config.CorrelationWindow
		if inactive || expired {
			flushed = append(flushed, candidate.group())
			grouper.retained -= len(candidate.events)
			continue
		}
		active = append(active, candidate)
	}
	clear(grouper.candidates[len(active):])
	grouper.candidates = active
	return flushed
}

func (grouper *StreamGrouper) Drain() []Group {
	groups := make([]Group, 0, len(grouper.candidates))
	for _, candidate := range grouper.candidates {
		groups = append(groups, candidate.group())
	}
	grouper.candidates = nil
	grouper.retained = 0
	return groups
}

func (grouper *StreamGrouper) ActiveCandidates() int {
	return len(grouper.candidates)
}

func (grouper *StreamGrouper) flushOldest() Group {
	oldestIndex := 0
	for index := 1; index < len(grouper.candidates); index++ {
		if grouper.candidates[index].lastSeen.Before(grouper.candidates[oldestIndex].lastSeen) {
			oldestIndex = index
		}
	}
	oldest := grouper.candidates[oldestIndex]
	lastIndex := len(grouper.candidates) - 1
	copy(grouper.candidates[oldestIndex:], grouper.candidates[oldestIndex+1:])
	grouper.candidates[lastIndex] = nil
	grouper.candidates = grouper.candidates[:lastIndex]
	grouper.retained -= len(oldest.events)
	return oldest.group()
}

type candidate struct {
	host        string
	containerID string
	startTime   time.Time
	lastSeen    time.Time
	events      []Event
	pids        map[int]bool
	artifacts   map[string]bool
	maxEvents   int
	dropped     int
}

func newCandidate(event Event, maxEvents int) *candidate {
	created := &candidate{
		host:        event.Host,
		containerID: event.ContainerID,
		startTime:   event.Timestamp,
		pids:        make(map[int]bool),
		artifacts:   make(map[string]bool),
		maxEvents:   maxEvents,
	}
	created.add(event)
	return created
}

func (candidate *candidate) add(event Event) {
	candidate.events = append(candidate.events, event)
	if candidate.lastSeen.IsZero() || event.Timestamp.After(candidate.lastSeen) {
		candidate.lastSeen = event.Timestamp
	}
	if event.PID > 0 {
		candidate.pids[event.PID] = true
	}
	if event.FilePath != "" {
		candidate.artifacts[event.FilePath] = true
	}
	if candidate.maxEvents > 0 && len(candidate.events) > candidate.maxEvents {
		copy(candidate.events, candidate.events[len(candidate.events)-candidate.maxEvents:])
		clear(candidate.events[candidate.maxEvents:])
		candidate.events = candidate.events[:candidate.maxEvents]
		candidate.dropped++
		candidate.rebuildIndexes()
	}
}

func (candidate *candidate) rebuildIndexes() {
	candidate.pids = make(map[int]bool)
	candidate.artifacts = make(map[string]bool)
	for _, event := range candidate.events {
		if event.PID > 0 {
			candidate.pids[event.PID] = true
		}
		if event.FilePath != "" {
			candidate.artifacts[event.FilePath] = true
		}
	}
}

func (candidate *candidate) group() Group {
	return Group{Events: candidate.events, DroppedEvents: candidate.dropped}
}

func (candidate *candidate) related(event Event, correlationWindow time.Duration) bool {
	if candidate.host != event.Host || candidate.containerID != event.ContainerID {
		return false
	}
	if event.Timestamp.Sub(candidate.startTime) > correlationWindow {
		return false
	}
	if candidate.pids[event.PID] || candidate.pids[event.PPID] {
		return true
	}
	if event.FilePath != "" && candidate.artifacts[event.FilePath] {
		return true
	}
	return event.ExecutablePath != "" && candidate.artifacts[event.ExecutablePath]
}
