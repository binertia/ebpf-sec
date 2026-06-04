//go:build linux && (amd64 || arm64)

package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"runtime-guard/internal/events"
)

func TestEnrichContainerMetadata(t *testing.T) {
	procRoot := t.TempDir()
	writeProcFile(t, procRoot, "4120/cgroup", "0::/kubepods.slice/kubepods-besteffort-pod1234.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n")
	writeProcFile(t, procRoot, "4120/root/etc/hostname", "pod-runtime\n")

	event := events.Event{}
	enrichContainerMetadata(&event, procRoot, 4120, nil)

	if event.ContainerID != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("container id = %q", event.ContainerID)
	}
	if event.ContainerName != "pod-runtime" {
		t.Fatalf("container name = %q, want pod-runtime", event.ContainerName)
	}
}

func TestEnrichContainerMetadataSkipsMissingData(t *testing.T) {
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "4120"), 0o755); err != nil {
		t.Fatal(err)
	}

	event := events.Event{ContainerID: "existing"}
	enrichContainerMetadata(&event, procRoot, 4120, nil)

	if event.ContainerID != "existing" {
		t.Fatalf("container id changed to %q", event.ContainerID)
	}
	if event.ContainerName != "" {
		t.Fatalf("container name = %q, want empty", event.ContainerName)
	}
}

func TestReadProcContainerIDSkipsKubernetesPodUID(t *testing.T) {
	procRoot := t.TempDir()
	want := strings.Repeat("f", 64)
	writeProcFile(t, procRoot, "4120/cgroup",
		"0::/kubepods.slice/kubepods-burstable-pod01234567_89ab_cdef_0123_456789abcdef.slice/cri-containerd-"+want+".scope\n")

	if got := readProcContainerID(procRoot, 4120); got != want {
		t.Fatalf("container id = %q, want %q", got, want)
	}
}

func TestEnrichContainerMetadataDoesNotUseHostHostname(t *testing.T) {
	procRoot := t.TempDir()
	writeProcFile(t, procRoot, "4120/cgroup", "0::/user.slice/user-1000.slice/session-1.scope\n")
	writeProcFile(t, procRoot, "4120/root/etc/hostname", "host-name\n")

	event := events.Event{}
	enrichContainerMetadata(&event, procRoot, 4120, nil)

	if event.ContainerID != "" || event.ContainerName != "" {
		t.Fatalf("container metadata = %#v, %#v, want empty", event.ContainerID, event.ContainerName)
	}
}

func TestContainerMetadataCacheInvalidatesReusedPID(t *testing.T) {
	procRoot := t.TempDir()
	firstID := strings.Repeat("a", 64)
	secondID := strings.Repeat("b", 64)
	writeProcFile(t, procRoot, "4120/stat", procStat(4120, "100"))
	writeProcFile(t, procRoot, "4120/cgroup", "0::/docker/"+firstID+"\n")
	writeProcFile(t, procRoot, "4120/root/etc/hostname", "first\n")

	cache := newContainerMetadataCache()
	if got := cache.lookup(procRoot, 4120); got.id != firstID || got.hostname != "first" {
		t.Fatalf("first metadata = %#v", got)
	}

	writeProcFile(t, procRoot, "4120/stat", procStat(4120, "200"))
	writeProcFile(t, procRoot, "4120/cgroup", "0::/docker/"+secondID+"\n")
	writeProcFile(t, procRoot, "4120/root/etc/hostname", "second\n")
	if got := cache.lookup(procRoot, 4120); got.id != secondID || got.hostname != "second" {
		t.Fatalf("reused PID metadata = %#v", got)
	}
}

func procStat(pid int, startTime string) string {
	return fmt.Sprintf("%d (runtime-guard-test) S %s%s\n", pid, strings.Repeat("0 ", 18), startTime)
}
