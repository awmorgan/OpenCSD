package ocsd

import "testing"

func TestPktTypeHelpers(t *testing.T) {
	addr := PktVAddr{
		Size:      VA64Bit,
		Val:       0x12345678,
		PktBits:   12,
		ValidBits: 40,
	}
	if addr.Size != VA64Bit || addr.Val != 0x12345678 || addr.PktBits != 12 || addr.ValidBits != 40 {
		t.Fatalf("unexpected packet address helper contents: %+v", addr)
	}

	sized := PktByteSzVal{Val: 0xABCD, SizeBytes: 4, ValidBytes: 2}
	if sized.Val != 0xABCD || sized.SizeBytes != 4 || sized.ValidBytes != 2 {
		t.Fatalf("unexpected byte/size helper contents: %+v", sized)
	}

	if AtomPattern != 0 || AtomRepeat != 1 {
		t.Fatalf("unexpected atom packet type constants: %d %d", AtomPattern, AtomRepeat)
	}
}
