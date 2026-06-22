package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
)

const (
	btfMagic           = 0xeb9f
	btfHeaderLen       = 24
	btfLayoutHeaderLen = 32
)

var (
	kernelSpecOnce sync.Once
	kernelSpec     *btf.Spec
	kernelSpecErr  error
)

// LoadKernelSpec loads kernel BTF while tolerating Linux 7.1's optional BTF
// layout section. cilium/ebpf v0.21 still rejects the new non-zero header
// trailer before it can ignore or consume the layout metadata.
func LoadKernelSpec() (*btf.Spec, error) {
	kernelSpecOnce.Do(func() {
		kernelSpec, kernelSpecErr = loadKernelSpec()
	})
	if kernelSpecErr != nil {
		return nil, kernelSpecErr
	}
	return kernelSpec.Copy(), nil
}

func loadKernelSpec() (*btf.Spec, error) {
	spec, err := btf.LoadKernelSpec()
	if err == nil {
		return spec, nil
	}
	if !strings.Contains(err.Error(), "non-zero trailer") {
		return nil, err
	}

	raw, readErr := os.ReadFile("/sys/kernel/btf/vmlinux")
	if readErr != nil {
		return nil, err
	}

	raw, stripErr := stripBTFLayout(raw)
	if stripErr != nil {
		return nil, fmt.Errorf("strip BTF layout: %w", stripErr)
	}

	spec, loadErr := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if loadErr != nil {
		return nil, fmt.Errorf("load stripped kernel BTF: %w", loadErr)
	}
	return spec, nil
}

func stripBTFLayout(raw []byte) ([]byte, error) {
	if len(raw) < btfHeaderLen {
		return nil, fmt.Errorf("BTF header length %d is shorter than %d", len(raw), btfHeaderLen)
	}

	bo, err := btfByteOrder(raw)
	if err != nil {
		return nil, err
	}

	hdrLen := bo.Uint32(raw[4:8])
	if hdrLen < btfHeaderLen {
		return nil, fmt.Errorf("BTF header length %d is shorter than %d", hdrLen, btfHeaderLen)
	}
	if uint64(hdrLen) > uint64(len(raw)) {
		return nil, fmt.Errorf("BTF header length %d exceeds data size %d", hdrLen, len(raw))
	}
	if hdrLen == btfHeaderLen || !hasNonZero(raw[btfHeaderLen:hdrLen]) {
		return raw, nil
	}
	if hdrLen < btfLayoutHeaderLen {
		return nil, fmt.Errorf("unsupported BTF header length %d", hdrLen)
	}
	if hasNonZero(raw[btfLayoutHeaderLen:hdrLen]) {
		return nil, fmt.Errorf("unsupported non-zero BTF header extension after layout fields")
	}

	typeOff := bo.Uint32(raw[8:12])
	typeLen := bo.Uint32(raw[12:16])
	strOff := bo.Uint32(raw[16:20])
	strLen := bo.Uint32(raw[20:24])
	layoutOff := bo.Uint32(raw[24:28])
	layoutLen := bo.Uint32(raw[28:32])

	typeStart, typeEnd, err := btfSectionRange(raw, hdrLen, typeOff, typeLen, "type")
	if err != nil {
		return nil, err
	}
	strStart, strEnd, err := btfSectionRange(raw, hdrLen, strOff, strLen, "string")
	if err != nil {
		return nil, err
	}
	if layoutLen > 0 {
		if layoutLen%4 != 0 {
			return nil, fmt.Errorf("BTF layout section length %d is not 4-byte aligned", layoutLen)
		}
		if _, _, err := btfSectionRange(raw, hdrLen, layoutOff, layoutLen, "layout"); err != nil {
			return nil, err
		}
	}

	outLen := uint64(btfHeaderLen) + uint64(typeLen) + uint64(strLen)
	if outLen > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("BTF data size %d exceeds platform int", outLen)
	}

	out := make([]byte, int(outLen))
	copy(out[:btfHeaderLen], raw[:btfHeaderLen])
	bo.PutUint32(out[4:8], btfHeaderLen)
	bo.PutUint32(out[8:12], 0)
	bo.PutUint32(out[12:16], typeLen)
	bo.PutUint32(out[16:20], typeLen)
	bo.PutUint32(out[20:24], strLen)

	copy(out[btfHeaderLen:btfHeaderLen+int(typeLen)], raw[typeStart:typeEnd])
	copy(out[btfHeaderLen+int(typeLen):], raw[strStart:strEnd])
	return out, nil
}

func btfByteOrder(raw []byte) (binary.ByteOrder, error) {
	switch {
	case binary.LittleEndian.Uint16(raw[:2]) == btfMagic:
		return binary.LittleEndian, nil
	case binary.BigEndian.Uint16(raw[:2]) == btfMagic:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("invalid BTF magic %x", raw[:2])
	}
}

func btfSectionRange(raw []byte, hdrLen, off, size uint32, name string) (int, int, error) {
	start := uint64(hdrLen) + uint64(off)
	end := start + uint64(size)
	if end < start || end > uint64(len(raw)) {
		return 0, 0, fmt.Errorf("BTF %s section range [%d,%d) exceeds data size %d", name, start, end, len(raw))
	}
	return int(start), int(end), nil
}

func hasNonZero(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return true
		}
	}
	return false
}
