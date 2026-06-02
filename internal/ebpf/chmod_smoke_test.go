//go:build ebpf_smoke && linux && amd64

package ebpf

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestChmodCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	collector, err := NewChmodCollector()
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
			if event.FilePath == path &&
				event.Metadata["added_execute_bit"] == true &&
				event.Metadata["outcome"] == "success" {
				cancel()
				return
			}
		case err := <-errors:
			if err != nil {
				t.Fatal(err)
			}
			t.Fatal("collector stopped before observing chmod")
		case <-ticker.C:
			if err := os.Chmod(path, 0o700); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for chmod event")
		}
	}
}
