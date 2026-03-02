package common

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestAddrReturnStack(t *testing.T) {
	s := NewAddrReturnStack()

	if s.IsActive() {
		t.Errorf("Should default to inactive")
	}

	// Push while inactive shouldn't do anything
	s.Push(0x1000, ocsd.ISAThumb2)
	if s.numEntries != 0 {
		t.Errorf("Push while inactive modified stack")
	}

	s.SetActive(true)

	s.SetPopPending()
	if !s.PopPending() {
		t.Errorf("SetPopPending failed")
	}
	s.ClearPopPending()

	s.SetTInfoWaitAddr()
	if !s.IsTInfoWaitAddr() {
		t.Errorf("SetTInfoWaitAddr failed")
	}
	s.Push(0x2000, ocsd.ISAArm) // shouldn't push because tInfoWaitAddr
	if s.numEntries != 0 {
		t.Errorf("Push while tInfoWaitAddr modified stack")
	}
	s.ClearTInfoWaitAddr()

	// Push 5 items
	s.Push(0x100, ocsd.ISAArm)
	s.Push(0x104, ocsd.ISAArm)
	s.Push(0x108, ocsd.ISAArm)
	s.Push(0x10C, ocsd.ISAArm)
	s.Push(0x110, ocsd.ISAArm)

	if s.numEntries != 5 {
		t.Errorf("Expected 5 entries, got %d", s.numEntries)
	}

	var isa ocsd.ISA
	addr := s.Pop(&isa)
	if addr != 0x110 || isa != ocsd.ISAArm || s.numEntries != 4 {
		t.Errorf("Pop failed, got 0x%X", addr)
	}

	s.Flush()
	if s.numEntries != 0 {
		t.Errorf("Flush failed")
	}

	// Test underflow
	s.Pop(&isa)
	if !s.Overflow() {
		t.Errorf("Underflow/Overflow tracking failed")
	}

	s.Flush()
	// Test wrap around
	for i := range 20 {
		s.Push(ocsd.VAddr(0x1000+i*4), ocsd.ISAArm)
	}
	if s.numEntries != 16 {
		t.Errorf("Expected max 16 entries, got %d", s.numEntries)
	}

	// Because of ring buffer logic, the oldest 4 should be overwritten.
	// The newest is 0x1000 + 19*4 = 0x104C
	addr = s.Pop(&isa)
	if addr != 0x104C {
		t.Errorf("Expected 0x104C after wrap, got 0x%X", addr)
	}
}
