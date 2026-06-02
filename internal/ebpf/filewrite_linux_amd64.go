//go:build linux && amd64

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"runtime-guard/internal/events"
)

const (
	writeSyscallNumber    = 1
	pwriteSyscallNumber   = 18
	writevSyscallNumber   = 20
	pwritevSyscallNumber  = 296
	pwritev2SyscallNumber = 328
)

type FileWriteCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type fileWriteRecord struct {
	KernelTimestampNS uint64
	PID               uint32
	UID               uint32
	Comm              [commSize]byte
	FD                int32
	Syscall           uint32
	RequestedCount    uint64
}

func NewFileWriteCollector() (*FileWriteCollector, error) {
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &FileWriteCollector{host: host, procRoot: "/proc", containerCache: newContainerMetadataCache()}, nil
}

// Run emits path-backed file write attempts. Descriptors 0-2 and descriptors
// that no longer resolve to filesystem paths are discarded in the hot path.
func (collector *FileWriteCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.RingBuf,
		Name:       "rg_write_rb",
		MaxEntries: ringBufferSize,
	})
	if err != nil {
		return fmt.Errorf("create file write ring buffer: %w", err)
	}
	defer records.Close()

	drops, err := newDropCounterMap("rg_write_drop")
	if err != nil {
		return fmt.Errorf("create file write drop counter: %w", err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	program, err := cebpf.NewProgram(fileWriteProgramSpec(records.FD(), drops.FD()))
	if err != nil {
		return fmt.Errorf("load file write raw tracepoint program: %w", err)
	}
	defer program.Close()

	hook, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: program,
	})
	if err != nil {
		return fmt.Errorf("attach sys_enter raw tracepoint: %w", err)
	}
	defer hook.Close()

	reader, err := ringbuf.NewReader(records)
	if err != nil {
		return fmt.Errorf("open file write ring buffer reader: %w", err)
	}
	defer reader.Close()

	readerDone := make(chan struct{})
	defer close(readerDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = reader.Close()
		case <-readerDone:
		}
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read file write ring buffer: %w", err)
		}

		raw, err := decodeFileWriteRecord(record.RawSample)
		if err != nil {
			return err
		}
		event, ok := collector.normalize(raw)
		if !ok {
			continue
		}

		select {
		case sink <- event:
		case <-ctx.Done():
			return nil
		}
	}
}

func (collector *FileWriteCollector) Stats() Stats {
	return collector.metrics.stats()
}

func fileWriteProgramSpec(ringBufferFD, dropCounterFD int) *cebpf.ProgramSpec {
	const (
		fdOffset      = int16(32)
		syscallOffset = int16(36)
		countOffset   = int16(40)
	)
	recordSize := int16(binary.Size(fileWriteRecord{}))
	recordStart := -recordSize
	tempValue := recordStart - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
		asm.JEq.Imm(asm.R8, writeSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, pwriteSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, writevSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, pwritevSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, pwritev2SyscallNumber, "capture"),
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("capture"),
	}
	for offset := recordStart; offset < 0; offset += 8 {
		instructions = append(instructions, asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
	}

	instructions = append(instructions,
		asm.StoreMem(asm.RFP, recordStart+syscallOffset, asm.R8, asm.Word),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, recordStart, asm.R0, asm.DWord),

		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, recordStart+8, asm.R0, asm.Word),

		asm.FnGetCurrentUidGid.Call(),
		asm.StoreMem(asm.RFP, recordStart+12, asm.R0, asm.Word),

		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(recordStart+16)),
		asm.Mov.Imm(asm.R2, commSize),
		asm.FnGetCurrentComm.Call(),
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDIOffset, asm.RFP, tempValue, recordStart+fdOffset, asm.Word)...,
	)
	instructions = append(instructions,
		asm.LoadMem(asm.R7, asm.RFP, recordStart+fdOffset, asm.Word),
		asm.JLE.Imm(asm.R7, 2, "exit"),
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDXOffset, asm.RFP, tempValue, recordStart+countOffset, asm.DWord)...,
	)
	instructions = append(instructions,
		asm.LoadMapPtr(asm.R1, ringBufferFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(recordStart)),
		asm.Mov.Imm(asm.R3, int32(recordSize)),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
	)
	instructions = append(instructions, countRingBufferDrop(dropCounterFD, tempValue)...)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)

	return &cebpf.ProgramSpec{
		Name:         "rg_file_write",
		Type:         cebpf.RawTracepoint,
		License:      "GPL",
		Instructions: instructions,
	}
}

func decodeFileWriteRecord(raw []byte) (fileWriteRecord, error) {
	var decoded fileWriteRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode file write record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode file write record: %w", err)
	}
	return decoded, nil
}

func (collector *FileWriteCollector) normalize(raw fileWriteRecord) (events.Event, bool) {
	pid := int(raw.PID)
	path := readProcFD(collector.procRoot, pid, int(raw.FD))
	if path == "" {
		return events.Event{}, false
	}

	timestamp := time.Now().UTC()
	ppid := readProcPPID(collector.procRoot, pid)
	executablePath := readProcExe(collector.procRoot, pid)
	processName := cString(raw.Comm[:])
	if executablePath != "" {
		processName = filepath.Base(executablePath)
	}

	event := events.Event{
		EventID:           fmt.Sprintf("file-write-%d-%d-%d", timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         events.TypeFileWrite,
		ExecutablePath:    executablePath,
		CWD:               readProcCWD(collector.procRoot, pid),
		FilePath:          path,
		Metadata: map[string]any{
			"source":              "ebpf_raw_tracepoint_sys_enter",
			"kernel_timestamp_ns": raw.KernelTimestampNS,
			"syscall":             fileWriteSyscallName(raw.Syscall),
			"fd":                  raw.FD,
			"requested_count":     raw.RequestedCount,
			"count_kind":          fileWriteCountKind(raw.Syscall),
			"outcome":             "attempt",
		},
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event, true
}

func fileWriteSyscallName(number uint32) string {
	switch number {
	case writeSyscallNumber:
		return "write"
	case pwriteSyscallNumber:
		return "pwrite64"
	case writevSyscallNumber:
		return "writev"
	case pwritevSyscallNumber:
		return "pwritev"
	case pwritev2SyscallNumber:
		return "pwritev2"
	default:
		return "unknown"
	}
}

func fileWriteCountKind(number uint32) string {
	switch number {
	case writevSyscallNumber, pwritevSyscallNumber, pwritev2SyscallNumber:
		return "iovecs"
	default:
		return "bytes"
	}
}
