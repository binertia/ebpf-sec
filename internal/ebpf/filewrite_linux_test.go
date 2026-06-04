//go:build linux && (amd64 || arm64)

package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeFileWriteRecord(t *testing.T) {
	procRoot := t.TempDir()
	writeProcFile(t, procRoot, "4120/status", "Name:\tcurl\nPPid:\t4112\n")
	writeProcFile(t, procRoot, "4112/comm", "sh\n")
	if err := os.MkdirAll(filepath.Join(procRoot, "4120/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/curl", filepath.Join(procRoot, "4120/exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/var/www", filepath.Join(procRoot, "4120/cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/payload", filepath.Join(procRoot, "4120/fd/8")); err != nil {
		t.Fatal(err)
	}

	raw := fileWriteRecord{
		KernelTimestampNS:           123456,
		CompletionKernelTimestampNS: 123789,
		ReturnValue:                 512,
		PID:                         4120,
		UID:                         33,
		FD:                          8,
		Syscall:                     writeSyscallNumber,
		RequestedCount:              512,
	}
	copy(raw.Comm[:], "curl")

	collector := &FileWriteCollector{host: "devbox-01", procRoot: procRoot}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected file write event to be normalized")
	}

	if event.FilePath != "/tmp/payload" {
		t.Fatalf("file path = %q, want /tmp/payload", event.FilePath)
	}
	if got := event.Metadata["syscall"]; got != "write" {
		t.Fatalf("syscall = %#v, want write", got)
	}
	if got := event.Metadata["requested_count"]; got != uint64(512) {
		t.Fatalf("requested count = %#v, want uint64(512)", got)
	}
	if got := event.Metadata["count_kind"]; got != "bytes" {
		t.Fatalf("count kind = %#v, want bytes", got)
	}
	if got := event.Metadata["outcome"]; got != "success" {
		t.Fatalf("outcome = %#v, want success", got)
	}
	if got := event.Metadata["written_bytes"]; got != int64(512) {
		t.Fatalf("written bytes = %#v, want int64(512)", got)
	}
}

func TestNormalizeFileWriteRecordIncludesFailure(t *testing.T) {
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "4120/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/payload", filepath.Join(procRoot, "4120/fd/8")); err != nil {
		t.Fatal(err)
	}

	collector := &FileWriteCollector{host: "devbox-01", procRoot: procRoot}
	event, ok := collector.normalize(fileWriteRecord{PID: 4120, FD: 8, ReturnValue: -13})
	if !ok {
		t.Fatal("expected failed file write event to be normalized")
	}
	if got := event.Metadata["outcome"]; got != "failed" {
		t.Fatalf("outcome = %#v, want failed", got)
	}
	if got := event.Metadata["errno"]; got != int64(13) {
		t.Fatalf("errno = %#v, want int64(13)", got)
	}
	if got := event.Metadata["written_bytes"]; got != int64(0) {
		t.Fatalf("written bytes = %#v, want int64(0)", got)
	}
}

func TestNormalizeFileWriteRecordSkipsNonFilesystemDescriptor(t *testing.T) {
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "4120/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pipe:[1234]", filepath.Join(procRoot, "4120/fd/8")); err != nil {
		t.Fatal(err)
	}

	collector := &FileWriteCollector{procRoot: procRoot}
	if _, ok := collector.normalize(fileWriteRecord{PID: 4120, FD: 8}); ok {
		t.Fatal("expected non-filesystem descriptor to be skipped")
	}
}
