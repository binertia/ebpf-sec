//go:build linux && arm64

package ebpf

const (
	syscallArg0Offset = 0
	syscallArg1Offset = 8
	syscallArg2Offset = 16

	execveSyscallNumber  = 221
	connectSyscallNumber = 203

	writeSyscallNumber    = 64
	pwriteSyscallNumber   = 68
	writevSyscallNumber   = 66
	pwritevSyscallNumber  = 70
	pwritev2SyscallNumber = 287

	chmodSyscallNumber     = 0
	fchmodSyscallNumber    = 52
	fchmodatSyscallNumber  = 53
	fchmodat2SyscallNumber = 452
	hasChmodSyscall        = false
)
