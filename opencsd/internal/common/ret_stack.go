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
	Active        bool
	PopPending    bool
	TInfoWaitAddr bool
	Overflow      bool
	Stack         [retStackCap]RetStackElement
	Head          int // points to oldest element
	Count         int // number of valid elements
}

// NewAddrReturnStack returns a new initialised AddrReturnStack.
func NewAddrReturnStack() *AddrReturnStack {
	s := &AddrReturnStack{}
	s.Flush()
	return s
}

// Push pushes addr/isa onto the top of the stack. When the stack is already
// at capacity the oldest (bottom) entry is overwritten.
func (s *AddrReturnStack) Push(addr ocsd.VAddr, isa ocsd.ISA) {
	if s.Active && !s.TInfoWaitAddr {
		if s.Count == retStackCap {
			s.Head = (s.Head + 1) % retStackCap
			s.Count--
		}
		tail := (s.Head + s.Count) % retStackCap
		s.Stack[tail] = RetStackElement{RetAddr: addr, RetISA: isa}
		s.Count++
		s.PopPending = false
	}
}

// Pop removes and returns the top entry. If the stack is empty it returns the
// VAMask sentinel and sets the overflow flag (matching the original C++
// behaviour where numEntries went negative).
func (s *AddrReturnStack) Pop(isa *ocsd.ISA) ocsd.VAddr {
	var addr ocsd.VAddr = ocsd.VAddr(ocsd.VAMask)
	if s.Active {
		if s.Count > 0 {
			top := (s.Head + s.Count - 1) % retStackCap
			elem := s.Stack[top]
			addr = elem.RetAddr
			*isa = elem.RetISA
			s.Stack[top] = RetStackElement{} // zero before decrement
			s.Count--
			s.Overflow = false
		} else {
			// Match C++ behaviour: an empty pop signals underflow.
			s.Overflow = true
		}
		s.PopPending = false
	}
	return addr
}

// Flush clears the stack and resets the overflow flag.
func (s *AddrReturnStack) Flush() {
	s.Head = 0
	s.Count = 0
	s.Overflow = false
	s.PopPending = false
}

// Overflow returns true when the last Pop call was against an empty stack.
