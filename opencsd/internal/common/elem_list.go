package common

import (
	"sync"

	"opencsd/internal/ocsd"
)

// traceElemPool recycles *ocsd.TraceElement allocations so that the hot
// decode path avoids repeated heap allocation.
var traceElemPool = sync.Pool{
	New: func() any { return ocsd.NewTraceElement() },
}

// getPoolElem leases a TraceElement from the pool, ensuring it is fully
// reset to its initial state before use (prevents data leakage between
// successive decoding passes).
func getPoolElem() *ocsd.TraceElement {
	e := traceElemPool.Get().(*ocsd.TraceElement)
	// Zero the entire struct first: Init() does not reset ElemType, so a
	// pooled element would otherwise retain its previous ElemType value.
	*e = ocsd.TraceElement{}
	e.Init()
	return e
}

// putPoolElem returns a TraceElement to the pool. It initialises the element
// before returning so that pool objects are always in a clean state.
func putPoolElem(e *ocsd.TraceElement) {
	e.Init()
	traceElemPool.Put(e)
}

// elemSlot pairs a TraceElement pointer with the packet index at which it
// was produced.
type elemSlot struct {
	elem     *ocsd.TraceElement
	pktIndex ocsd.TrcIndex
}

// DrainedElement is the transport value returned by ElemList.Drain() and
// ElemStack.Drain(). It carries a value copy of the element together with the
// packet byte-index at which the element was originally produced, preserving
// the historical index rather than the index of the packet that triggered the
// drain (e.g. a Commit packet).
type DrainedElement struct {
	Index ocsd.TrcIndex
	Elem  ocsd.TraceElement
}

// ─────────────────────────────────────────────────────────────────────────────
// ElemList
// ─────────────────────────────────────────────────────────────────────────────

// ElemList implements OcsdGenElemList.
//
// All elements live in a single flat slice (elems). numPend is a tail-boundary:
// the last numPend elements are held pending (not yet committed for sending).
// The committed window is elems[0 : len(elems)-numPend].
type ElemList struct {
	elems   []elemSlot
	numPend int
	csID    uint8
	sendIf  ocsd.GenElemProcessor
}

// NewElemList creates a new, empty ElemList.
func NewElemList() *ElemList {
	return &ElemList{
		elems: make([]elemSlot, 0, 16),
	}
}

func (l *ElemList) SetSendIf(sendIf ocsd.GenElemProcessor) {
	l.sendIf = sendIf
}

func (l *ElemList) SetCSID(csID uint8) {
	l.csID = csID
}

// Reset discards all elements, returning their TraceElement pointers to the
// pool.
func (l *ElemList) Reset() {
	for i := range l.elems {
		putPoolElem(l.elems[i].elem)
		l.elems[i].elem = nil // prevent GC-root leak in backing array
	}
	l.elems = l.elems[:0]
	l.numPend = 0
}

// NextElem leases an element from the pool, appends it to the slice, and
// returns a pointer for the caller to populate.
func (l *ElemList) NextElem(trcPktIdx ocsd.TrcIndex) *ocsd.TraceElement {
	e := getPoolElem()
	l.elems = append(l.elems, elemSlot{elem: e, pktIndex: trcPktIdx})
	return e
}

// NumElem returns the total number of elements (committed + pending).
func (l *ElemList) NumElem() int {
	return len(l.elems)
}

// ElemType returns the element type at logical index entryN.
func (l *ElemList) ElemType(entryN int) ocsd.GenElemType {
	if entryN >= 0 && entryN < len(l.elems) {
		return l.elems[entryN].elem.ElemType
	}
	return ocsd.GenElemUnknown
}

// PendLastNElem marks the last n elements as pending. It simply sets the
// numPend boundary; no elements are moved.
func (l *ElemList) PendLastNElem(n int) {
	if n > 0 && n <= len(l.elems) {
		l.numPend = n
	}
}

// CommitAllPendElem commits all pending elements for sending.
func (l *ElemList) CommitAllPendElem() {
	l.numPend = 0
}

// CancelPendElem discards the pending tail, returning elements to the pool.
func (l *ElemList) CancelPendElem() {
	if l.numPend == 0 {
		return
	}
	start := len(l.elems) - l.numPend
	for i := start; i < len(l.elems); i++ {
		putPoolElem(l.elems[i].elem)
		l.elems[i].elem = nil // prevent GC-root leak before reslice
	}
	l.elems = l.elems[:start]
	l.numPend = 0
}

// NumPendElem returns the number of pending elements.
func (l *ElemList) NumPendElem() int {
	return l.numPend
}

// ElemToSend returns true when there is at least one committed element.
func (l *ElemList) ElemToSend() bool {
	return len(l.elems)-l.numPend > 0
}

// SendElements dispatches committed (non-pending) elements to the registered
// receiver, removing each from the slice after dispatch.
func (l *ElemList) SendElements() error {
	if l.sendIf == nil {
		return ocsd.ErrNotInit
	}
	out := l.sendIf
	if out == nil {
		return ocsd.ErrNotInit
	}
	var outErr error
	for l.ElemToSend() && ocsd.IsDataContErr(outErr) {
		slot := l.elems[0]
		err := out.TraceElemIn(slot.pktIndex, l.csID, slot.elem)
		if ocsd.IsDataWaitErr(err) {
			outErr = ocsd.ErrWait
		} else {
			outErr = err
		}
		l.elems[0].elem = nil // nil-zero before reslice to release GC root
		l.elems = l.elems[1:]
		putPoolElem(slot.elem)
	}
	return outErr
}

// Drain returns a value-copy of every committed (non-pending) element, each
// paired with its original packet index, and removes them from the list.
// Pending elements (the last numPend slots) are preserved unchanged.
func (l *ElemList) Drain() []DrainedElement {
	committed := len(l.elems) - l.numPend
	if committed <= 0 {
		return nil
	}
	out := make([]DrainedElement, committed)
	for i := range committed {
		out[i] = DrainedElement{Index: l.elems[i].pktIndex, Elem: *l.elems[i].elem}
		putPoolElem(l.elems[i].elem)
		l.elems[i].elem = nil // release GC root after pool return
	}
	// Shift any pending slots to the front.
	copy(l.elems, l.elems[committed:])
	// Nil-zero the now-duplicate tail entries to release GC roots.
	tail := len(l.elems) - committed
	for i := tail; i < len(l.elems); i++ {
		l.elems[i].elem = nil
	}
	l.elems = l.elems[:l.numPend]
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ElemStack
// ─────────────────────────────────────────────────────────────────────────────

// ElemStack implements OcsdGenElemStack.
//
// Elements accumulate forward in a flat slice. The send cursor (sendElemIdx)
// tracks how far through the slice has already been dispatched.
type ElemStack struct {
	elems       []elemSlot
	elemToSend  int
	sendElemIdx int
	csID        uint8
	sendIf      ocsd.GenElemProcessor
}

// NewElemStack creates a new, empty ElemStack.
func NewElemStack() *ElemStack {
	return &ElemStack{
		elems: make([]elemSlot, 0, 4),
	}
}

func (s *ElemStack) SetSendIf(sendIf ocsd.GenElemProcessor) {
	s.sendIf = sendIf
}

func (s *ElemStack) SetCSID(csID uint8) {
	s.csID = csID
}

// currElemIdx returns the index of the last-added element.
func (s *ElemStack) currElemIdx() int {
	n := len(s.elems)
	if n == 0 {
		return 0
	}
	return n - 1
}

// CurrElem returns a pointer to the most recently added element.
func (s *ElemStack) CurrElem() *ocsd.TraceElement {
	return s.elems[s.currElemIdx()].elem
}

// ResetElemStack resets the stack, preserving persistent context data from
// the current element into position 0.
func (s *ElemStack) ResetElemStack() error {
	s.resetIndexes()
	return nil
}

func (s *ElemStack) resetIndexes() {
	if len(s.elems) == 0 {
		// Nothing to preserve; allocate a fresh base element.
		e := getPoolElem()
		s.elems = append(s.elems[:0], elemSlot{elem: e})
		s.sendElemIdx = 0
		s.elemToSend = 0
		return
	}

	// Preserve persistent context data from the current top element into a
	// fresh element at position 0, then discard everything else.
	curr := s.elems[len(s.elems)-1].elem
	base := getPoolElem()
	base.CopyPersistentData(curr)

	// Return all existing elements to the pool.
	for i := range s.elems {
		putPoolElem(s.elems[i].elem)
		s.elems[i].elem = nil
	}
	s.elems = s.elems[:0]
	s.elems = append(s.elems, elemSlot{elem: base})

	s.sendElemIdx = 0
	s.elemToSend = 0
}

// AddElem appends a new element slot. If there are already elements pending
// send it copies persistent data forward, matching the original semantics.
func (s *ElemStack) AddElem(trcPktIdx ocsd.TrcIndex) error {
	if s.elemToSend > 0 {
		// Copy persistent data from the current top to the new element.
		e := getPoolElem()
		e.CopyPersistentData(s.elems[len(s.elems)-1].elem)
		s.elems = append(s.elems, elemSlot{elem: e, pktIndex: trcPktIdx})
	} else {
		// Re-use the existing slot at position 0 (or create one if empty).
		if len(s.elems) == 0 {
			e := getPoolElem()
			s.elems = append(s.elems, elemSlot{elem: e, pktIndex: trcPktIdx})
		} else {
			s.elems[len(s.elems)-1].pktIndex = trcPktIdx
		}
	}
	s.elemToSend++
	return nil
}

// SetCurrElemIdx updates the packet index of the current (last) element.
func (s *ElemStack) SetCurrElemIdx(trcPktIdx ocsd.TrcIndex) {
	s.elems[s.currElemIdx()].pktIndex = trcPktIdx
}

// AddElemType appends a new element and immediately sets its type.
func (s *ElemStack) AddElemType(trcPktIdx ocsd.TrcIndex, elemType ocsd.GenElemType) error {
	err := s.AddElem(trcPktIdx)
	if err == nil {
		s.CurrElem().SetType(elemType)
	}
	return err
}

// NumElemToSend returns the number of elements pending dispatch.
func (s *ElemStack) NumElemToSend() int {
	return s.elemToSend
}

// SendElements dispatches all queued elements to the registered receiver.
func (s *ElemStack) SendElements() error {
	if s.sendIf == nil {
		return ocsd.ErrNotInit
	}
	out := s.sendIf
	if out == nil {
		return ocsd.ErrNotInit
	}
	var outErr error
	for s.elemToSend > 0 && ocsd.IsDataContErr(outErr) {
		slot := s.elems[s.sendElemIdx]
		err := out.TraceElemIn(slot.pktIndex, s.csID, slot.elem)
		if ocsd.IsDataWaitErr(err) {
			outErr = ocsd.ErrWait
		} else {
			outErr = err
		}
		s.elemToSend--
		s.sendElemIdx++
	}
	if s.elemToSend == 0 {
		s.resetIndexes()
	}
	return outErr
}

// Drain returns a value-copy of every element queued for sending, each paired
// with its original packet index, and resets the stack (calling resetIndexes,
// which preserves persistent arch context). Returns nil if nothing is queued.
func (s *ElemStack) Drain() []DrainedElement {
	if s.elemToSend == 0 {
		return nil
	}
	out := make([]DrainedElement, s.elemToSend)
	for i := 0; i < s.elemToSend; i++ {
		slot := s.elems[s.sendElemIdx+i]
		out[i] = DrainedElement{Index: slot.pktIndex, Elem: *slot.elem}
	}
	s.resetIndexes()
	return out
}
