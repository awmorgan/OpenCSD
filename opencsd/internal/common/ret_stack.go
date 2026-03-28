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
	stack         [retStackCap]RetStackElement
	head          int // points to oldest element
	count         int // number of valid elements
}

// NewAddrReturnStack returns a new initialised AddrReturnStack.
func NewAddrReturnStack() *AddrReturnStack {
	s := &AddrReturnStack{}
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
// at capacity the oldest (bottom) entry is overwritten.
func (s *AddrReturnStack) Push(addr ocsd.VAddr, isa ocsd.ISA) {
	if s.active && !s.tInfoWaitAddr {
		if s.count == retStackCap {
			s.head = (s.head + 1) % retStackCap
			s.count--
		}
		tail := (s.head + s.count) % retStackCap
		s.stack[tail] = RetStackElement{RetAddr: addr, RetISA: isa}
		s.count++
		s.popPending = false
	}
}

// Pop removes and returns the top entry. If the stack is empty it returns the
// VAMask sentinel and sets the overflow flag (matching the original C++
// behaviour where numEntries went negative).
func (s *AddrReturnStack) Pop(isa *ocsd.ISA) ocsd.VAddr {
	var addr ocsd.VAddr = ocsd.VAddr(ocsd.VAMask)
	if s.active {
		if s.count > 0 {
			top := (s.head + s.count - 1) % retStackCap
			elem := s.stack[top]
			addr = elem.RetAddr
			*isa = elem.RetISA
			s.stack[top] = RetStackElement{} // zero before decrement
			s.count--
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
	s.head = 0
	s.count = 0
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
