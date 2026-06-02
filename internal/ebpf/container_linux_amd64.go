//go:build linux && amd64

package ebpf

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"runtime-guard/internal/events"
)

const (
	defaultContainerCacheEntries = 4096
	defaultContainerCacheTTL     = 30 * time.Second
	maxContainerHostnameBytes    = 256
)

var (
	runtimeContainerComponentPattern = regexp.MustCompile(`(?i)^(?:docker|cri-containerd|containerd|crio|libpod)-([a-f0-9]{12,64})(?:\.scope)?$`)
	bareContainerComponentPattern    = regexp.MustCompile(`(?i)^[a-f0-9]{64}$`)
)

type containerMetadata struct {
	id       string
	hostname string
}

type containerCacheEntry struct {
	metadata  containerMetadata
	startTime string
	expiresAt time.Time
}

type containerMetadataCache struct {
	mu         sync.Mutex
	entries    map[int]containerCacheEntry
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
}

func newContainerMetadataCache() *containerMetadataCache {
	return &containerMetadataCache{
		entries:    make(map[int]containerCacheEntry),
		maxEntries: defaultContainerCacheEntries,
		ttl:        defaultContainerCacheTTL,
		now:        time.Now,
	}
}

func enrichContainerMetadata(event *events.Event, procRoot string, pid int, cache *containerMetadataCache) {
	if event == nil || pid <= 0 {
		return
	}

	var metadata containerMetadata
	if cache != nil {
		metadata = cache.lookup(procRoot, pid)
	} else {
		metadata = readProcContainerMetadata(procRoot, pid)
	}
	if metadata.id == "" {
		return
	}
	event.ContainerID = metadata.id
	event.ContainerName = metadata.hostname
}

func (cache *containerMetadataCache) lookup(procRoot string, pid int) containerMetadata {
	startTime := readProcStartTime(procRoot, pid)
	if startTime == "" {
		return readProcContainerMetadata(procRoot, pid)
	}

	now := cache.now()
	cache.mu.Lock()
	if entry, found := cache.entries[pid]; found && entry.startTime == startTime && now.Before(entry.expiresAt) {
		cache.mu.Unlock()
		return entry.metadata
	}
	cache.mu.Unlock()

	metadata := readProcContainerMetadata(procRoot, pid)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.entries) >= cache.maxEntries {
		cache.evictOne(now)
	}
	cache.entries[pid] = containerCacheEntry{
		metadata:  metadata,
		startTime: startTime,
		expiresAt: now.Add(cache.ttl),
	}
	return metadata
}

func (cache *containerMetadataCache) evictOne(now time.Time) {
	for pid, entry := range cache.entries {
		if !now.Before(entry.expiresAt) {
			delete(cache.entries, pid)
			return
		}
	}
	for pid := range cache.entries {
		delete(cache.entries, pid)
		return
	}
}

func readProcContainerMetadata(procRoot string, pid int) containerMetadata {
	id := readProcContainerID(procRoot, pid)
	if id == "" {
		return containerMetadata{}
	}
	return containerMetadata{
		id:       id,
		hostname: readProcContainerHostname(procRoot, pid),
	}
}

func readProcContainerID(procRoot string, pid int) string {
	contents, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(contents), "\n") {
		for _, component := range strings.Split(line, "/") {
			if match := runtimeContainerComponentPattern.FindStringSubmatch(component); len(match) == 2 {
				return strings.ToLower(match[1])
			}
			if bareContainerComponentPattern.MatchString(component) {
				return strings.ToLower(component)
			}
		}
	}
	return ""
}

func readProcContainerHostname(procRoot string, pid int) string {
	file, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "root", "etc", "hostname"))
	if err != nil {
		return ""
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxContainerHostnameBytes))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(contents))
}

func readProcStartTime(procRoot string, pid int) string {
	contents, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	end := strings.LastIndexByte(string(contents), ')')
	if end == -1 {
		return ""
	}
	fields := strings.Fields(string(contents[end+1:]))
	if len(fields) <= 19 {
		return ""
	}
	return fields[19]
}
