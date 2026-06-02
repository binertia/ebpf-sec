//go:build linux && amd64

package ebpf

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/cilium/ebpf"
)

func TestProgramSpecsMarshal(t *testing.T) {
	specs := map[string]*ebpf.ProgramSpec{
		"execve":     execveProgramSpec(1, 2),
		"connect":    connectProgramSpec(1, 2),
		"file_write": fileWriteProgramSpec(1, 2),
		"chmod":      chmodProgramSpec(1, 2),
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			if err := spec.Instructions.Marshal(io.Discard, binary.LittleEndian); err != nil {
				t.Fatal(err)
			}
		})
	}
}
