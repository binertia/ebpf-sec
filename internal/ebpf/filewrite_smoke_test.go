//go:build ebpf_smoke && linux && (amd64 || arm64)

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestFileWriteCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	path := filepath.Join(t.TempDir(), "payload")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	collector, err := NewFileWriteCollector()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sink := make(chan events.Event)
	errors := make(chan error, 1)
	go func() {
		errors <- collector.Run(ctx, sink)
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case event := <-sink:
			if event.FilePath == path && event.Metadata["outcome"] == "success" {
				cancel()
				waitForCollectorShutdown(t, errors)
				return
			}
		case err := <-errors:
			if err != nil {
				t.Fatal(err)
			}
			t.Fatal("collector stopped before observing file write")
		case <-ticker.C:
			if _, err := file.WriteString("fixture"); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for file write event")
		}
	}
}
