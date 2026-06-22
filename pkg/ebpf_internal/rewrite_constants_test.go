package internal

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestRewriteConstantsHandlesHiddenDatasecVars(t *testing.T) {
	constName := "PARAM"
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			".rodata": {
				Contents: []ebpf.MapKV{{Key: uint32(0), Value: make([]byte, 8)}},
				Value: &btf.Datasec{
					Name: ".rodata",
					Size: 8,
					Vars: []btf.VarSecinfo{{
						Type:   &btf.Var{Name: constName, Type: &btf.Int{Name: "int", Size: 4}},
						Offset: 2,
						Size:   4,
					}},
				},
			},
		},
	}

	if err := RewriteConstants(spec, map[string]interface{}{constName: uint32(0x01020304)}); err != nil {
		t.Fatalf("rewrite constants: %v", err)
	}

	data := spec.Maps[".rodata"].Contents[0].Value.([]byte)
	if got := binary.LittleEndian.Uint32(data[2:6]); got != 0x01020304 {
		t.Fatalf("unexpected rewritten constant: %#x", got)
	}
}

func TestRewriteConstantsReportsMissingConst(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}}

	err := RewriteConstants(spec, map[string]interface{}{"PARAM": uint32(1)})
	if err == nil || !strings.Contains(err.Error(), "some constants are missing from .rodata: PARAM") {
		t.Fatalf("unexpected error: %v", err)
	}
}
