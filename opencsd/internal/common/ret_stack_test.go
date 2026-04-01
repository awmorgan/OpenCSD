package common

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestAddrReturnStack(t *testing.T) {
	s := NewAddrReturnStack()

	if s.Active {
		t.Errorf("Should default to inactive")
	}

	// Push while inactive shouldn't do anything
	s.Push(0x1000, ocsd.ISAThumb2)
	if s.Count != 0 {
		t.Errorf("Push while inactive modified stack")
	}

	s.Active = true

	if s.Active {
		s.PopPending = true
	}
	if !s.PopPending {
		t.Errorf("SetPopPending failed")
	}
	s.PopPending = false

	s.TInfoWaitAddr = true
	if !s.TInfoWaitAddr {
		t.Errorf("SetTInfoWaitAddr failed")
	}
	s.Push(0x2000, ocsd.ISAArm) // shouldn't push because tInfoWaitAddr
	if s.Count != 0 {
		t.Errorf("Push while tInfoWaitAddr modified stack")
	}
	s.TInfoWaitAddr = false

	// Push 5 items
	s.Push(0x100, ocsd.ISAArm)
	s.Push(0x104, ocsd.ISAArm)
	s.Push(0x108, ocsd.ISAArm)
	s.Push(0x10C, ocsd.ISAArm)
	s.Push(0x110, ocsd.ISAArm)

	if s.Count != 5 {
		t.Errorf("Expected 5 entries, got %d", s.Count)
	}

	addr, isa, ok := s.Pop()
	if !ok || addr != 0x110 || isa != ocsd.ISAArm || s.Count != 4 {
		t.Errorf("Pop failed, got 0x%X", addr)
	}

	s.Flush()
	if s.Count != 0 {
		t.Errorf("Flush failed")
	}

	// Test underflow
	addr, isa, ok = s.Pop()
	if ok || addr != ocsd.VAddr(ocsd.VAMask) || isa != 0 {
		t.Errorf("Underflow handling failed")
	}

	s.Flush()
	// Test wrap around
	for i := range 20 {
		s.Push(ocsd.VAddr(0x1000+i*4), ocsd.ISAArm)
	}
	if s.Count != 16 {
		t.Errorf("Expected max 16 entries, got %d", s.Count)
	}

	// Because of ring buffer logic, the oldest 4 should be overwritten.
	// The newest is 0x1000 + 19*4 = 0x104C
	addr, isa, ok = s.Pop()
	if !ok || addr != 0x104C || isa != ocsd.ISAArm {
		t.Errorf("Expected 0x104C after wrap, got 0x%X", addr)
	}
}
