package internal

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// RewriteConstants replaces .rodata constants, including hidden static consts
// that cilium/ebpf v0.21 no longer exposes through CollectionSpec.Variables.
func RewriteConstants(spec *ebpf.CollectionSpec, constants map[string]interface{}) error {
	replaced := make(map[string]bool, len(constants))

	for mapName, mapSpec := range spec.Maps {
		if !strings.HasPrefix(mapName, ".rodata") {
			continue
		}

		datasec, ok := mapSpec.Value.(*btf.Datasec)
		if !ok {
			continue
		}
		data, err := dataSectionBytes(mapSpec)
		if err != nil {
			return fmt.Errorf("map %s: %w", mapName, err)
		}

		data = append([]byte(nil), data...)
		changed := false
		for _, variable := range datasec.Vars {
			name := variable.Type.TypeName()
			replacement, ok := constants[name]
			if !ok {
				continue
			}
			if _, ok := variable.Type.(*btf.Var); !ok {
				return fmt.Errorf("section %s: unexpected type %T for variable %s", mapName, variable.Type, name)
			}
			if replaced[name] {
				return fmt.Errorf("section %s: duplicate variable %s", mapName, name)
			}

			end := variable.Offset + variable.Size
			if end < variable.Offset || int(end) > len(data) {
				return fmt.Errorf("section %s: offset %d(+%d) for variable %s is out of bounds", mapName, variable.Offset, variable.Size, name)
			}
			buf, err := marshalConstant(replacement, int(variable.Size))
			if err != nil {
				return fmt.Errorf("marshaling constant replacement %s: %w", name, err)
			}
			copy(data[variable.Offset:end], buf)
			replaced[name] = true
			changed = true
		}

		if changed {
			mapSpec.Contents[0].Value = data
		}
	}

	missing := missingConstants(constants, replaced)
	if len(missing) > 0 {
		return fmt.Errorf("some constants are missing from .rodata: %s", strings.Join(missing, ", "))
	}
	return nil
}

func dataSectionBytes(mapSpec *ebpf.MapSpec) ([]byte, error) {
	if n := len(mapSpec.Contents); n != 1 {
		return nil, fmt.Errorf("expected one key, found %d", n)
	}
	key, ok := mapSpec.Contents[0].Key.(uint32)
	if !ok || key != 0 {
		return nil, fmt.Errorf("expected contents to have key 0")
	}
	value, ok := mapSpec.Contents[0].Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("value at first map key is %T, not []byte", mapSpec.Contents[0].Value)
	}
	return value, nil
}

func marshalConstant(value interface{}, size int) ([]byte, error) {
	var (
		buf []byte
		err error
	)
	switch v := value.(type) {
	case encoding.BinaryMarshaler:
		buf, err = v.MarshalBinary()
	case string:
		buf = []byte(v)
	case []byte:
		buf = v
	default:
		buf, err = binary.Append(nil, NativeEndian, v)
	}
	if err != nil {
		return nil, err
	}
	if len(buf) != size {
		return nil, fmt.Errorf("%T doesn't marshal to %d bytes", value, size)
	}
	return buf, nil
}

func missingConstants(constants map[string]interface{}, replaced map[string]bool) []string {
	missing := make([]string, 0, len(constants)-len(replaced))
	for name := range constants {
		if !replaced[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}
