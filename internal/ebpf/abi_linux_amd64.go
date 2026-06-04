//go:build linux && amd64

package ebpf

const (
	syscallArg0Offset = 112
	syscallArg1Offset = 104
	syscallArg2Offset = 96

	execveSyscallNumber  = 59
	connectSyscallNumber = 42

	writeSyscallNumber    = 1
	pwriteSyscallNumber   = 18
	writevSyscallNumber   = 20
	pwritevSyscallNumber  = 296
	pwritev2SyscallNumber = 328

	chmodSyscallNumber     = 90
	fchmodSyscallNumber    = 91
	fchmodatSyscallNumber  = 268
	fchmodat2SyscallNumber = 452
	hasChmodSyscall        = true
)
