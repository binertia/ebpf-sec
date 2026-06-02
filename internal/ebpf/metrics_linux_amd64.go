//go:build linux && amd64

package ebpf

import (
	"sync"
	"sync/atomic"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type collectorMetrics struct {
	mu                sync.RWMutex
	dropCounter       *cebpf.Map
	ringBufferDropped atomic.Uint64
}

func newDropCounterMap(name string) (*cebpf.Map, error) {
	return cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.Array,
		Name:       name,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
}

func (metrics *collectorMetrics) attachDropCounter(counter *cebpf.Map) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.dropCounter = counter
}

func (metrics *collectorMetrics) detachDropCounter(counter *cebpf.Map) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.dropCounter != counter {
		return
	}
	metrics.refreshLocked()
	metrics.dropCounter = nil
}

func (metrics *collectorMetrics) stats() Stats {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.refreshLocked()
	return Stats{RingBufferDropped: metrics.ringBufferDropped.Load()}
}

func (metrics *collectorMetrics) refreshLocked() {
	if metrics.dropCounter == nil {
		return
	}
	var dropped uint64
	if err := metrics.dropCounter.Lookup(uint32(0), &dropped); err == nil {
		metrics.ringBufferDropped.Store(dropped)
	}
}

func countRingBufferDrop(dropCounterFD int, keyOffset int16) asm.Instructions {
	return asm.Instructions{
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.StoreImm(asm.RFP, keyOffset, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, dropCounterFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(keyOffset)),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
	}
}
