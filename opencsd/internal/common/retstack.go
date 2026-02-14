package common

// ReturnStack mimics TrcAddrReturnStack.
// It tracks return addresses for function calls (BL, BLX) to predict
// destinations of returns (BX LR, POP {PC}) without explicit address packets.
type ReturnStack struct {
	stack [16]struct {
		Addr uint64
		ISA  Isa
	}
	headIdx    int
	numEntries int
	active     bool
}

func NewReturnStack() *ReturnStack {
	return &ReturnStack{
		active: true, // Default to active, can be disabled via config if needed
	}
}

func (rs *ReturnStack) SetActive(active bool) {
	rs.active = active
}

func (rs *ReturnStack) Flush() {
	rs.numEntries = 0
	rs.headIdx = 0
}

func (rs *ReturnStack) Push(addr uint64, isa Isa) {
	if !rs.active {
		return
	}
	// C++ logic: head_idx increments, masked by 0xF
	rs.headIdx = (rs.headIdx + 1) & 0xF
	rs.stack[rs.headIdx].Addr = addr
	rs.stack[rs.headIdx].ISA = isa

	if rs.numEntries < 16 {
		rs.numEntries++
	}
}

func (rs *ReturnStack) Pop() (uint64, Isa, bool) {
	if !rs.active || rs.numEntries == 0 {
		return 0, 0, false
	}

	addr := rs.stack[rs.headIdx].Addr
	isa := rs.stack[rs.headIdx].ISA

	rs.headIdx = (rs.headIdx - 1) & 0xF
	rs.numEntries--

	return addr, isa, true
}
