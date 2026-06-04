//go:build ebpf_smoke && linux && (amd64 || arm64)

package ebpf

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestExecveCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	collector, err := NewExecveCollector()
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
			if event.ExecutablePath == "/bin/true" {
				cancel()
				waitForCollectorShutdown(t, errors)
				return
			}
		case err := <-errors:
			if err != nil {
				t.Fatal(err)
			}
			t.Fatal("collector stopped before observing /bin/true")
		case <-ticker.C:
			if err := exec.Command("/bin/true").Run(); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for /bin/true execve event")
		}
	}
}
