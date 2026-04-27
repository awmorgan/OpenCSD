package ocsd

import "testing"

func TestPktTypeHelpers(t *testing.T) {
	addr := PktVAddr{Size: VA64Bit, Val: 0x12345678, PktBits: 12, ValidBits: 40}
	if want := (PktVAddr{Size: VA64Bit, Val: 0x12345678, PktBits: 12, ValidBits: 40}); addr != want {
		t.Fatalf("unexpected packet address helper contents: got %+v want %+v", addr, want)
	}

	sized := PktByteSzVal{Val: 0xABCD, SizeBytes: 4, ValidBytes: 2}
	if want := (PktByteSzVal{Val: 0xABCD, SizeBytes: 4, ValidBytes: 2}); sized != want {
		t.Fatalf("unexpected byte/size helper contents: got %+v want %+v", sized, want)
	}

	if AtomPattern != 0 || AtomRepeat != 1 {
		t.Fatalf("unexpected atom packet type constants: %d %d", AtomPattern, AtomRepeat)
	}
}
