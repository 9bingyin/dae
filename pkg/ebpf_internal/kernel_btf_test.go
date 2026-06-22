package internal

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestStripBTFLayout(t *testing.T) {
	raw := makeRawBTFWithLayout(t)

	stripped, err := stripBTFLayout(raw)
	if err != nil {
		t.Fatalf("strip BTF layout: %v", err)
	}
	if got := binary.LittleEndian.Uint32(stripped[4:8]); got != btfHeaderLen {
		t.Fatalf("unexpected BTF header length: got %d, want %d", got, btfHeaderLen)
	}
	if got := binary.LittleEndian.Uint32(stripped[8:12]); got != 0 {
		t.Fatalf("unexpected type offset: got %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(stripped[16:20]); got != 0 {
		t.Fatalf("unexpected string offset: got %d, want 0", got)
	}
	if !bytes.Equal(stripped[btfHeaderLen:], []byte{0}) {
		t.Fatalf("unexpected stripped payload: %v", stripped[btfHeaderLen:])
	}
	if _, err := btf.LoadSpecFromReader(bytes.NewReader(stripped)); err != nil {
		t.Fatalf("load stripped BTF: %v", err)
	}
}

func TestStripBTFLayoutKeepsZeroHeaderTrailer(t *testing.T) {
	raw := make([]byte, btfHeaderLen+4+1)
	binary.LittleEndian.PutUint16(raw[0:2], btfMagic)
	raw[2] = 1
	binary.LittleEndian.PutUint32(raw[4:8], btfHeaderLen+4)
	binary.LittleEndian.PutUint32(raw[16:20], 0)
	binary.LittleEndian.PutUint32(raw[20:24], 1)

	stripped, err := stripBTFLayout(raw)
	if err != nil {
		t.Fatalf("strip BTF layout: %v", err)
	}
	if !bytes.Equal(stripped, raw) {
		t.Fatalf("zero header trailer should stay unchanged")
	}
}

func makeRawBTFWithLayout(t *testing.T) []byte {
	t.Helper()

	raw := make([]byte, btfLayoutHeaderLen+1+4)
	binary.LittleEndian.PutUint16(raw[0:2], btfMagic)
	raw[2] = 1
	binary.LittleEndian.PutUint32(raw[4:8], btfLayoutHeaderLen)
	binary.LittleEndian.PutUint32(raw[8:12], 0)
	binary.LittleEndian.PutUint32(raw[12:16], 0)
	binary.LittleEndian.PutUint32(raw[16:20], 0)
	binary.LittleEndian.PutUint32(raw[20:24], 1)
	binary.LittleEndian.PutUint32(raw[24:28], 1)
	binary.LittleEndian.PutUint32(raw[28:32], 4)
	copy(raw[btfLayoutHeaderLen+1:], []byte{1, 2, 3, 4})
	return raw
}
