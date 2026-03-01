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
	// Format 1 (Non-CA)
	if !p.UpdateAtomFromPHdr(0x00, false) {
		t.Error("fmt1 allowed non-cycleAcc")
	}
	if p.PHdrFmt != 1 {
		t.Errorf("expected fmt 1, got %d", p.PHdrFmt)
	}

	// Format 2 (Non-CA)
	if !p.UpdateAtomFromPHdr(0x02, false) {
		t.Error("fmt2 allowed non-cycleAcc")
	}
	if p.PHdrFmt != 2 {
		t.Errorf("expected fmt 2, got %d", p.PHdrFmt)
	}

	// Format 1 (CA)
	if !p.UpdateAtomFromPHdr(0x84, true) {
		t.Error("fmt1 allowed cycleAcc")
	}
	if p.PHdrFmt != 1 {
		t.Errorf("expected fmt 1 (CA), got %d", p.PHdrFmt)
	}

	// Format 4 (CA) - 0x92 is fmt 4 (1001 0010)
	// (0x92 & 0xA3) == 0x82 AND (0x92 & 0x10) == 0x10
	if !p.UpdateAtomFromPHdr(0x92, true) {
		t.Error("fmt4 allowed cycleAcc")
	}
	if p.PHdrFmt != 4 {
		t.Errorf("expected fmt 4, got %d", p.PHdrFmt)
	}
}
