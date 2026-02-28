package etmv3

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestPacket(t *testing.T) {
	p := &Packet{}
	p.ResetState()

	if p.Type != PktNoError {
		t.Error("expected PktNoError")
	}
	if p.CurrISA != ocsd.ISAArm {
		t.Error("expected ISAArm")
	}

	p.Type = PktBadSequence
	if !p.IsBadPacket() {
		t.Error("expected bad packet")
	}

	p.UpdateAddress(0x1234, 16)
	if p.Addr != 0x1234 {
		t.Error("addr mismatch")
	}
	p.UpdateAddress(0x5600, 8)
	if p.Addr != 0x1200 {
		t.Errorf("addr mismatch %x", p.Addr)
	}

	p.SetException(ocsd.ExcpFIQ, 4, true, false, 0, 1)
	if p.Exception.Type != ocsd.ExcpFIQ {
		t.Error("exception type mismatch")
	}
	if !p.Exception.Present {
		t.Error("expected present")
	}

	_ = p.String()

	p.Type = PktPHdr
	_ = p.String()

	p.Type = PktISync
	_ = p.String()

	p.Type = PktBranchAddress
	_ = p.String()

	p.Type = PktNotSync
	if p.Type.String() != "I_NOT_SYNC" {
		t.Error("stringer mismatch")
	}
	p.Type = PktType(99)
	if p.Type.String() != "Unknown PktType" {
		t.Error("stringer mismatch for unknown")
	}

	// Test UpdateAtomFromPHdr
	// Format 4
	if p.UpdateAtomFromPHdr(0x00, true) {
		t.Error("fmt4 not allowed cycleAcc")
	}
	if !p.UpdateAtomFromPHdr(0x00, false) {
		t.Error("fmt4 allowed non-cycleAcc")
	}
	if p.PHdrFmt != 4 {
		t.Error("expected fmt 4")
	}

	// Fmt 3
	if !p.UpdateAtomFromPHdr(0x42, false) {
		t.Error("fmt3")
	}
	p.UpdateAtomFromPHdr(0x00, false) // 0x00 fmt4
	p.UpdateAtomFromPHdr(0x01, false) // 0x01 fmt3
	p.UpdateAtomFromPHdr(0x10, false) // 0x10 fmt3
	p.UpdateAtomFromPHdr(0x11, false) // 0x11 fmt4
	p.UpdateAtomFromPHdr(0x08, false) // 0x08 fmt2
	p.UpdateAtomFromPHdr(0x02, false) // 0x02 fmt1
}
