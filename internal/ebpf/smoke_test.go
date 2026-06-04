//go:build ebpf_smoke && linux && (amd64 || arm64)

package ebpf

import (
	"testing"
	"time"
)

func waitForCollectorShutdown(t *testing.T, errors <-chan error) {
	t.Helper()

	select {
	case err := <-errors:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("collector did not stop after cancellation")
	}
}
