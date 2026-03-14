package etmv4

import "testing"

func TestProcessorInitPacketStateClearsConditionalState(t *testing.T) {
	p := NewProcessor(&Config{})
	p.currPacketData = []byte{0xAA, 0xBB}
	p.currPacket.CondInstr = CondInstr{
		CondCKey:   0x23,
		NumCElem:   4,
		CondKeySet: true,
	}
	p.currPacket.CondResult = CondResult{
		CondRKey0:  0x12,
		CondRKey1:  0x34,
		Res0:       0xA,
		Res1:       0x5,
		KeyRes0Set: true,
		KeyRes1Set: true,
	}

	p.initPacketState()

	if len(p.currPacketData) != 0 {
		t.Fatalf("expected packet data cleared, got %d bytes", len(p.currPacketData))
	}
	if p.currPacket.CondInstr.CondKeySet {
		t.Fatalf("expected CondInstr.CondKeySet to be cleared")
	}
	if p.currPacket.CondResult.KeyRes0Set {
		t.Fatalf("expected CondResult.KeyRes0Set to be cleared")
	}
	if p.currPacket.CondResult.KeyRes1Set {
		t.Fatalf("expected CondResult.KeyRes1Set to be cleared")
	}
	if p.currPacket.CondInstr.CondCKey != 0 || p.currPacket.CondResult.CondRKey0 != 0 || p.currPacket.CondResult.CondRKey1 != 0 {
		t.Fatalf("expected conditional packet data to be reset")
	}
}

func TestProcessorIAtomF6MatchesReferencePattern(t *testing.T) {
	p := NewProcessor(&Config{})
	p.currPacket.Type = PktAtomF6

	p.iAtom(0x00)

	if p.currPacket.Atom.Num != 4 {
		t.Fatalf("expected 4 atoms, got %d", p.currPacket.Atom.Num)
	}
	if got := p.currPacket.Atom.EnBits & 0xF; got != 0xF {
		t.Fatalf("expected low atom bits 0xF for EEEE pattern, got 0x%X", got)
	}

	p.currPacket.Type = PktAtomF6
	p.iAtom(0x20)

	if got := p.currPacket.Atom.EnBits & 0xF; got != 0x7 {
		t.Fatalf("expected low atom bits 0x7 for EEEN pattern, got 0x%X", got)
	}
}

func TestProcessorExtractCondResultMasksResultNibble(t *testing.T) {
	p := NewProcessor(&Config{})
	buf := []byte{0xDA, 0x01}

	var key uint32
	var result uint8
	consumed := p.extractCondResult(buf, 0, &key, &result)

	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if result != 0xA {
		t.Fatalf("expected result nibble 0xA, got 0x%X", result)
	}
	if key != 0xD {
		t.Fatalf("expected conditional key 0xD, got 0x%X", key)
	}
}
