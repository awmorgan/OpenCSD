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
type AddrReturnStack struct {
	Active        bool
	PopPending    bool
	TInfoWaitAddr bool
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
// VAMask sentinel, a zero-value ISA, and false.
func (s *AddrReturnStack) Pop() (ocsd.VAddr, ocsd.ISA, bool) {
	addr := ocsd.VAddr(ocsd.VAMask)
	var isa ocsd.ISA
	if s.Active {
		if s.Count > 0 {
			top := (s.Head + s.Count - 1) % retStackCap
			elem := s.Stack[top]
			addr = elem.RetAddr
			isa = elem.RetISA
			s.Stack[top] = RetStackElement{} // zero before decrement
			s.Count--
			s.PopPending = false
			return addr, isa, true
		}
		s.PopPending = false
	}
	return addr, isa, false
}

// Flush clears the stack state.
func (s *AddrReturnStack) Flush() {
	s.Head = 0
	s.Count = 0
	s.PopPending = false
}
