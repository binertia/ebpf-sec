//go:build linux && amd64

package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeChmodRecord(t *testing.T) {
	procRoot := t.TempDir()
	writeProcFile(t, procRoot, "4112/status", "Name:\tsh\nPPid:\t4101\n")
	writeProcFile(t, procRoot, "4101/comm", "nginx\n")
	if err := os.MkdirAll(filepath.Join(procRoot, "4112"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/dash", filepath.Join(procRoot, "4112/exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/var/www", filepath.Join(procRoot, "4112/cwd")); err != nil {
		t.Fatal(err)
	}

	raw := chmodRecord{KernelTimestampNS: 123456, PID: 4112, UID: 33, Mode: 0o755, Syscall: chmodSyscallNumber}
	copy(raw.Comm[:], "sh")
	copy(raw.FilePath[:], "/tmp/payload")

	collector := &ChmodCollector{host: "devbox-01", procRoot: procRoot}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected chmod event to be normalized")
	}

	if event.FilePath != "/tmp/payload" {
		t.Fatalf("file path = %q, want /tmp/payload", event.FilePath)
	}
	if got := event.Metadata["mode"]; got != "0755" {
		t.Fatalf("mode = %#v, want 0755", got)
	}
	if got := event.Metadata["added_execute_bit"]; got != true {
		t.Fatalf("added execute bit = %#v, want true", got)
	}
	if got := event.Metadata["syscall"]; got != "chmod" {
		t.Fatalf("syscall = %#v, want chmod", got)
	}
}

func TestNormalizeChmodRecordResolvesFchmodatPath(t *testing.T) {
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "4112/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(procRoot, "4112/fd/9")); err != nil {
		t.Fatal(err)
	}

	raw := chmodRecord{PID: 4112, Mode: 0o700, FD: 9, Syscall: fchmodatSyscallNumber}
	copy(raw.Comm[:], "sh")
	copy(raw.FilePath[:], "payload")

	collector := &ChmodCollector{host: "devbox-01", procRoot: procRoot}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected fchmodat event to be normalized")
	}
	if event.FilePath != "/tmp/payload" {
		t.Fatalf("file path = %q, want /tmp/payload", event.FilePath)
	}
}
