//go:build linux && amd64

package ebpf

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf/asm"
)

const ptRegsDXOffset = 96

func readRegisterArgument(ctx asm.Register, registerOffset int32, frame asm.Register, tempOffset, destinationOffset int16, size asm.Size) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R3, ctx, 0, asm.DWord),
		asm.Add.Imm(asm.R3, registerOffset),
		asm.Mov.Reg(asm.R1, frame),
		asm.Add.Imm(asm.R1, int32(tempOffset)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),
		asm.LoadMem(asm.R7, frame, tempOffset, asm.DWord),
		asm.StoreMem(frame, destinationOffset, asm.R7, size),
	}
}

func readPathArgument(ctx asm.Register, registerOffset int32, frame asm.Register, tempOffset, destinationOffset int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R3, ctx, 0, asm.DWord),
		asm.Add.Imm(asm.R3, registerOffset),
		asm.Mov.Reg(asm.R1, frame),
		asm.Add.Imm(asm.R1, int32(tempOffset)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),
		asm.LoadMem(asm.R3, frame, tempOffset, asm.DWord),
		asm.Mov.Reg(asm.R1, frame),
		asm.Add.Imm(asm.R1, int32(destinationOffset)),
		asm.Mov.Imm(asm.R2, filenameSize),
		asm.FnProbeReadUserStr.Call(),
	}
}

func readProcFD(procRoot string, pid, fd int) string {
	if pid <= 0 || fd < 0 {
		return ""
	}
	path, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "fd", strconv.Itoa(fd)))
	if err != nil || !filepath.IsAbs(path) {
		return ""
	}
	return filepath.Clean(path)
}

func resolveProcPath(procRoot string, pid, dirfd int, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	base := readProcCWD(procRoot, pid)
	if dirfd != atFDCWD {
		base = readProcFD(procRoot, pid, dirfd)
	}
	if base == "" || !filepath.IsAbs(base) {
		return ""
	}
	return filepath.Clean(filepath.Join(base, path))
}
