//go:build linux && amd64

package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeExecveRecord(t *testing.T) {
	procRoot := t.TempDir()
	writeProcFile(t, procRoot, "4120/status", "Name:\tcurl\nPPid:\t4112\n")
	writeProcFile(t, procRoot, "4112/comm", "sh\n")
	if err := os.MkdirAll(filepath.Join(procRoot, "4120"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/var/www", filepath.Join(procRoot, "4120/cwd")); err != nil {
		t.Fatal(err)
	}

	raw := execveRecord{KernelTimestampNS: 123456, PID: 4120, UID: 33}
	copy(raw.Comm[:], "sh")
	copy(raw.Filename[:], "/usr/bin/curl")

	collector := &ExecveCollector{host: "devbox-01", procRoot: procRoot}
	event := collector.normalize(raw)

	if event.Host != "devbox-01" {
		t.Fatalf("host = %q, want devbox-01", event.Host)
	}
	if event.PID != 4120 || event.PPID != 4112 {
		t.Fatalf("process IDs = pid:%d ppid:%d, want pid:4120 ppid:4112", event.PID, event.PPID)
	}
	if event.ProcessName != "curl" || event.ParentProcessName != "sh" {
		t.Fatalf("process names = %q <- %q, want curl <- sh", event.ProcessName, event.ParentProcessName)
	}
	if event.ExecutablePath != "/usr/bin/curl" {
		t.Fatalf("executable path = %q, want /usr/bin/curl", event.ExecutablePath)
	}
	if event.CWD != "/var/www" {
		t.Fatalf("cwd = %q, want /var/www", event.CWD)
	}
	if got := event.Metadata["kernel_timestamp_ns"]; got != uint64(123456) {
		t.Fatalf("kernel timestamp = %#v, want uint64(123456)", got)
	}
}

func writeProcFile(t *testing.T, procRoot, name, contents string) {
	t.Helper()
	path := filepath.Join(procRoot, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
