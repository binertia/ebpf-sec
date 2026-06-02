//go:build ebpf_smoke && linux && amd64

package ebpf

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestConnectCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	endpoint := listener.Addr().(*net.TCPAddr)

	collector, err := NewConnectCollector()
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
			if event.RemoteAddr == "127.0.0.1" && event.RemotePort == endpoint.Port {
				cancel()
				return
			}
		case err := <-errors:
			if err != nil {
				t.Fatal(err)
			}
			t.Fatal("collector stopped before observing the test connection")
		case <-ticker.C:
			connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err == nil {
				connection.Close()
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for IPv4 connect event")
		}
	}
}
