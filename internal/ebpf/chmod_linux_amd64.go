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
	chmodSyscallNumber     = 90
	fchmodSyscallNumber    = 91
	fchmodatSyscallNumber  = 268
	fchmodat2SyscallNumber = 452
	atFDCWD                = -100
)

type ChmodCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type chmodRecord struct {
	KernelTimestampNS uint64
	PID               uint32
	UID               uint32
	Comm              [commSize]byte
	FilePath          [filenameSize]byte
	FD                int32
	Mode              uint32
	Syscall           uint32
	_                 uint32
}

func NewChmodCollector() (*ChmodCollector, error) {
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &ChmodCollector{host: host, procRoot: "/proc", containerCache: newContainerMetadataCache()}, nil
}

// Run emits normalized chmod attempts. The execute-bit signal describes the
// requested mode; raw syscall entry does not expose whether the syscall later
// succeeded or whether the bit was newly added.
func (collector *ChmodCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.RingBuf,
		Name:       "rg_chmod_rb",
		MaxEntries: ringBufferSize,
	})
	if err != nil {
		return fmt.Errorf("create chmod ring buffer: %w", err)
	}
	defer records.Close()

	drops, err := newDropCounterMap("rg_chmod_drop")
	if err != nil {
		return fmt.Errorf("create chmod drop counter: %w", err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	program, err := cebpf.NewProgram(chmodProgramSpec(records.FD(), drops.FD()))
	if err != nil {
		return fmt.Errorf("load chmod raw tracepoint program: %w", err)
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
		return fmt.Errorf("open chmod ring buffer reader: %w", err)
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
			return fmt.Errorf("read chmod ring buffer: %w", err)
		}

		raw, err := decodeChmodRecord(record.RawSample)
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

func (collector *ChmodCollector) Stats() Stats {
	return collector.metrics.stats()
}

func chmodProgramSpec(ringBufferFD, dropCounterFD int) *cebpf.ProgramSpec {
	const (
		pathOffset    = int16(32)
		fdOffset      = int16(288)
		modeOffset    = int16(292)
		syscallOffset = int16(296)
	)
	recordSize := int16(binary.Size(chmodRecord{}))
	recordStart := -recordSize
	tempValue := recordStart - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
		asm.JEq.Imm(asm.R8, chmodSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, fchmodSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, fchmodatSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, fchmodat2SyscallNumber, "capture"),
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

		asm.JEq.Imm(asm.R8, chmodSyscallNumber, "chmod_path"),
		asm.JEq.Imm(asm.R8, fchmodSyscallNumber, "fchmod_fd"),
	)

	// fchmodat and fchmodat2: dirfd, pathname, mode.
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDIOffset, asm.RFP, tempValue, recordStart+fdOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgument(asm.R6, ptRegsSIOffset, asm.RFP, tempValue, recordStart+pathOffset)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDXOffset, asm.RFP, tempValue, recordStart+modeOffset, asm.Word)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))

	// chmod: pathname, mode.
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("chmod_path"),
	)
	instructions = append(instructions,
		readPathArgument(asm.R6, ptRegsDIOffset, asm.RFP, tempValue, recordStart+pathOffset)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsSIOffset, asm.RFP, tempValue, recordStart+modeOffset, asm.Word)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))

	// fchmod: fd, mode.
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("fchmod_fd"),
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDIOffset, asm.RFP, tempValue, recordStart+fdOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsSIOffset, asm.RFP, tempValue, recordStart+modeOffset, asm.Word)...,
	)

	instructions = append(instructions,
		asm.LoadMapPtr(asm.R1, ringBufferFD).WithSymbol("emit"),
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
		Name:         "rg_chmod",
		Type:         cebpf.RawTracepoint,
		License:      "GPL",
		Instructions: instructions,
	}
}

func decodeChmodRecord(raw []byte) (chmodRecord, error) {
	var decoded chmodRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode chmod record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode chmod record: %w", err)
	}
	return decoded, nil
}

func (collector *ChmodCollector) normalize(raw chmodRecord) (events.Event, bool) {
	pid := int(raw.PID)
	path := collector.resolvePath(pid, raw)
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
		EventID:           fmt.Sprintf("chmod-%d-%d-%d", timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         events.TypeChmod,
		ExecutablePath:    executablePath,
		CWD:               readProcCWD(collector.procRoot, pid),
		FilePath:          path,
		Metadata: map[string]any{
			"source":              "ebpf_raw_tracepoint_sys_enter",
			"kernel_timestamp_ns": raw.KernelTimestampNS,
			"syscall":             chmodSyscallName(raw.Syscall),
			"mode":                fmt.Sprintf("%04o", raw.Mode&0o7777),
			"added_execute_bit":   raw.Mode&0o111 != 0,
			"outcome":             "attempt",
		},
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event, true
}

func (collector *ChmodCollector) resolvePath(pid int, raw chmodRecord) string {
	switch raw.Syscall {
	case chmodSyscallNumber:
		return resolveProcPath(collector.procRoot, pid, atFDCWD, cString(raw.FilePath[:]))
	case fchmodSyscallNumber:
		return readProcFD(collector.procRoot, pid, int(raw.FD))
	case fchmodatSyscallNumber, fchmodat2SyscallNumber:
		return resolveProcPath(collector.procRoot, pid, int(raw.FD), cString(raw.FilePath[:]))
	default:
		return ""
	}
}

func chmodSyscallName(number uint32) string {
	switch number {
	case chmodSyscallNumber:
		return "chmod"
	case fchmodSyscallNumber:
		return "fchmod"
	case fchmodatSyscallNumber:
		return "fchmodat"
	case fchmodat2SyscallNumber:
		return "fchmodat2"
	default:
		return "unknown"
	}
}
