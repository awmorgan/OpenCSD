package common

import "opencsd/internal/ocsd"

// RetStackElement stores an address and ISA for the return stack.
type RetStackElement struct {
	RetAddr ocsd.VAddr
	RetISA  ocsd.ISA
}

const retStackCap = 16

// AddrReturnStack implements TrcAddrReturnStack.
//
// The stack is a plain []RetStackElement capped at retStackCap (16) entries.
// When the cap is exceeded the oldest entry is silently dropped (matching the
// original ring-buffer wrap-around semantics).
//
// A separate overflow flag tracks the case where Pop is called on an empty
// stack, reproducing the C++ behaviour that drove numEntries negative.
type AddrReturnStack struct {
	active        bool
	popPending    bool
	tInfoWaitAddr bool
	overflow      bool
	stack         []RetStackElement
}

// NewAddrReturnStack returns a new initialised AddrReturnStack.
func NewAddrReturnStack() *AddrReturnStack {
	s := &AddrReturnStack{}
	s.stack = make([]RetStackElement, 0, retStackCap)
	s.Flush()
	return s
}

func (s *AddrReturnStack) SetActive(active bool) {
	s.active = active
}

func (s *AddrReturnStack) IsActive() bool {
	return s.active
}

// Push pushes addr/isa onto the top of the stack. When the stack is already
// at capacity the oldest (bottom) entry is discarded before appending.
func (s *AddrReturnStack) Push(addr ocsd.VAddr, isa ocsd.ISA) {
	if s.active && !s.tInfoWaitAddr {
		if len(s.stack) >= retStackCap {
			// Drop oldest entry (bottom of slice) — same as ring-buffer wrap.
			s.stack[0] = RetStackElement{} // zero before reslice (value type, but good hygiene)
			s.stack = s.stack[1:]
		}
		s.stack = append(s.stack, RetStackElement{RetAddr: addr, RetISA: isa})
		s.popPending = false
	}
}

// Pop removes and returns the top entry. If the stack is empty it returns the
// VAMask sentinel and sets the overflow flag (matching the original C++
// behaviour where numEntries went negative).
func (s *AddrReturnStack) Pop(isa *ocsd.ISA) ocsd.VAddr {
	var addr ocsd.VAddr = ocsd.VAddr(ocsd.VAMask)
	if s.active {
		n := len(s.stack)
		if n > 0 {
			top := s.stack[n-1]
			addr = top.RetAddr
			*isa = top.RetISA
			s.stack[n-1] = RetStackElement{} // zero before reslice
			s.stack = s.stack[:n-1]
			s.overflow = false
		} else {
			// Match C++ behaviour: an empty pop signals underflow.
			s.overflow = true
		}
		s.popPending = false
	}
	return addr
}

// Flush clears the stack and resets the overflow flag.
func (s *AddrReturnStack) Flush() {
	s.stack = s.stack[:0]
	s.overflow = false
	s.popPending = false
}

// Overflow returns true when the last Pop call was against an empty stack.
func (s *AddrReturnStack) Overflow() bool {
	return s.overflow
}

func (s *AddrReturnStack) SetPopPending(pending bool) {
	if s.active {
		s.popPending = pending
		return
	}
	if !pending {
		s.popPending = false
	}
}

func (s *AddrReturnStack) PopPending() bool {
	return s.popPending
}

func (s *AddrReturnStack) SetTInfoWaitAddr(wait bool) {
	s.tInfoWaitAddr = wait
}

func (s *AddrReturnStack) IsTInfoWaitAddr() bool {
	return s.tInfoWaitAddr
}
