package common

import "opencsd/internal/ocsd"

// RetStackElement stores an address and ISA for the return stack.
type RetStackElement struct {
	RetAddr ocsd.VAddr
	RetISA  ocsd.ISA
}

// AddrReturnStack implements TrcAddrReturnStack.
// Provides a return stack cache for PTM/ETM address tracking.
type AddrReturnStack struct {
	active        bool
	popPending    bool
	tInfoWaitAddr bool
	headIdx       int
	numEntries    int
	stack         [16]RetStackElement
}

// NewAddrReturnStack returns a new initialized AddrReturnStack.
func NewAddrReturnStack() *AddrReturnStack {
	s := &AddrReturnStack{headIdx: 0}
	s.Flush()
	return s
}

func (s *AddrReturnStack) SetActive(active bool) {
	s.active = active
}

func (s *AddrReturnStack) IsActive() bool {
	return s.active
}

func (s *AddrReturnStack) Push(addr ocsd.VAddr, isa ocsd.ISA) {
	if s.active && !s.tInfoWaitAddr {
		s.headIdx++
		if s.headIdx >= 16 {
			s.headIdx = 0
		}
		s.stack[s.headIdx].RetAddr = addr
		s.stack[s.headIdx].RetISA = isa
		if s.numEntries < 16 {
			s.numEntries++
		}
		s.popPending = false
	}
}

func (s *AddrReturnStack) Pop(isa *ocsd.ISA) ocsd.VAddr {
	var addr ocsd.VAddr = ocsd.VAddr(ocsd.VAMask)
	if s.active {
		if s.numEntries > 0 {
			addr = s.stack[s.headIdx].RetAddr
			*isa = s.stack[s.headIdx].RetISA
			s.headIdx--
			if s.headIdx < 0 {
				s.headIdx = 15
			}
		}
		// Match C++ behavior: always decrement on pop when active.
		// An empty pop drives numEntries negative so Overflow() detects underflow.
		s.numEntries--
		s.popPending = false
	}
	return addr
}

func (s *AddrReturnStack) Flush() {
	s.numEntries = 0
	s.popPending = false
}

func (s *AddrReturnStack) Overflow() bool {
	return s.numEntries < 0
}

func (s *AddrReturnStack) SetPopPending() {
	if s.active {
		s.popPending = true
	}
}

func (s *AddrReturnStack) ClearPopPending() {
	s.popPending = false
}

func (s *AddrReturnStack) PopPending() bool {
	return s.popPending
}

func (s *AddrReturnStack) SetTInfoWaitAddr() {
	s.tInfoWaitAddr = true
}

func (s *AddrReturnStack) ClearTInfoWaitAddr() {
	s.tInfoWaitAddr = false
}

func (s *AddrReturnStack) IsTInfoWaitAddr() bool {
	return s.tInfoWaitAddr
}
