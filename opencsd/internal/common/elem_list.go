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

// ─────────────────────────────────────────────────────────────────────────────
// GenElemList
// ─────────────────────────────────────────────────────────────────────────────

// GenElemList implements OcsdGenElemList.
//
// All elements live in a single flat slice (elems). numPend is a tail-boundary:
// the last numPend elements are held pending (not yet committed for sending).
// The committed window is elems[0 : len(elems)-numPend].
type GenElemList struct {
	elems   []elemSlot
	numPend int
	csID    uint8
	sendIf  ocsd.GenElemProcessor
}

// NewGenElemList creates a new, empty GenElemList.
func NewGenElemList() *GenElemList {
	return &GenElemList{
		elems: make([]elemSlot, 0, 16),
	}
}

func (l *GenElemList) SetSendIf(sendIf ocsd.GenElemProcessor) {
	l.sendIf = sendIf
}

func (l *GenElemList) SetCSID(csID uint8) {
	l.csID = csID
}

// Reset discards all elements, returning their TraceElement pointers to the
// pool.
func (l *GenElemList) Reset() {
	for i := range l.elems {
		putPoolElem(l.elems[i].elem)
		l.elems[i].elem = nil // prevent GC-root leak in backing array
	}
	l.elems = l.elems[:0]
	l.numPend = 0
}

// NextElem leases an element from the pool, appends it to the slice, and
// returns a pointer for the caller to populate.
func (l *GenElemList) NextElem(trcPktIdx ocsd.TrcIndex) *ocsd.TraceElement {
	e := getPoolElem()
	l.elems = append(l.elems, elemSlot{elem: e, pktIndex: trcPktIdx})
	return e
}

// NumElem returns the total number of elements (committed + pending).
func (l *GenElemList) NumElem() int {
	return len(l.elems)
}

// ElemType returns the element type at logical index entryN.
func (l *GenElemList) ElemType(entryN int) ocsd.GenElemType {
	if entryN >= 0 && entryN < len(l.elems) {
		return l.elems[entryN].elem.ElemType
	}
	return ocsd.GenElemUnknown
}

// PendLastNElem marks the last n elements as pending. It simply sets the
// numPend boundary; no elements are moved.
func (l *GenElemList) PendLastNElem(n int) {
	if n > 0 && n <= len(l.elems) {
		l.numPend = n
	}
}

// CommitAllPendElem commits all pending elements for sending.
func (l *GenElemList) CommitAllPendElem() {
	l.numPend = 0
}

// CancelPendElem discards the pending tail, returning elements to the pool.
func (l *GenElemList) CancelPendElem() {
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
func (l *GenElemList) NumPendElem() int {
	return l.numPend
}

// ElemToSend returns true when there is at least one committed element.
func (l *GenElemList) ElemToSend() bool {
	return len(l.elems)-l.numPend > 0
}

// SendElements dispatches committed (non-pending) elements to the registered
// receiver, removing each from the slice after dispatch.
func (l *GenElemList) SendElements() ocsd.DatapathResp {
	if l.sendIf == nil {
		return ocsd.RespFatalNotInit
	}
	out := l.sendIf
	if out == nil {
		return ocsd.RespFatalNotInit
	}
	resp := ocsd.RespCont
	for l.ElemToSend() && ocsd.DataRespIsCont(resp) {
		slot := l.elems[0]
		var err error
		resp, err = out.TraceElemIn(slot.pktIndex, l.csID, slot.elem)
		if err != nil && !ocsd.DataRespIsFatal(resp) {
			resp = ocsd.RespFatalInvalidData
		}
		l.elems[0].elem = nil // nil-zero before reslice to release GC root
		l.elems = l.elems[1:]
		putPoolElem(slot.elem)
	}
	return resp
}

// ─────────────────────────────────────────────────────────────────────────────
// GenElemStack
// ─────────────────────────────────────────────────────────────────────────────

// GenElemStack implements OcsdGenElemStack.
//
// Elements accumulate forward in a flat slice. The send cursor (sendElemIdx)
// tracks how far through the slice has already been dispatched.
type GenElemStack struct {
	elems       []elemSlot
	elemToSend  int
	sendElemIdx int
	csID        uint8
	sendIf      ocsd.GenElemProcessor
}

// NewGenElemStack creates a new, empty GenElemStack.
func NewGenElemStack() *GenElemStack {
	return &GenElemStack{
		elems: make([]elemSlot, 0, 4),
	}
}

func (s *GenElemStack) SetSendIf(sendIf ocsd.GenElemProcessor) {
	s.sendIf = sendIf
}

func (s *GenElemStack) SetCSID(csID uint8) {
	s.csID = csID
}

// currElemIdx returns the index of the last-added element.
func (s *GenElemStack) currElemIdx() int {
	n := len(s.elems)
	if n == 0 {
		return 0
	}
	return n - 1
}

// CurrElem returns a pointer to the most recently added element.
func (s *GenElemStack) CurrElem() *ocsd.TraceElement {
	return s.elems[s.currElemIdx()].elem
}

// ResetElemStack resets the stack, preserving persistent context data from
// the current element into position 0.
func (s *GenElemStack) ResetElemStack() error {
	if s.sendIf == nil {
		return ocsd.ErrNotInit
	}
	s.resetIndexes()
	return nil
}

func (s *GenElemStack) resetIndexes() {
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
func (s *GenElemStack) AddElem(trcPktIdx ocsd.TrcIndex) error {
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
func (s *GenElemStack) SetCurrElemIdx(trcPktIdx ocsd.TrcIndex) {
	s.elems[s.currElemIdx()].pktIndex = trcPktIdx
}

// AddElemType appends a new element and immediately sets its type.
func (s *GenElemStack) AddElemType(trcPktIdx ocsd.TrcIndex, elemType ocsd.GenElemType) error {
	err := s.AddElem(trcPktIdx)
	if err == nil {
		s.CurrElem().SetType(elemType)
	}
	return err
}

// NumElemToSend returns the number of elements pending dispatch.
func (s *GenElemStack) NumElemToSend() int {
	return s.elemToSend
}

// SendElements dispatches all queued elements to the registered receiver.
func (s *GenElemStack) SendElements() ocsd.DatapathResp {
	if s.sendIf == nil {
		return ocsd.RespFatalNotInit
	}
	out := s.sendIf
	if out == nil {
		return ocsd.RespFatalNotInit
	}
	resp := ocsd.RespCont
	for s.elemToSend > 0 && ocsd.DataRespIsCont(resp) {
		slot := s.elems[s.sendElemIdx]
		var err error
		resp, err = out.TraceElemIn(slot.pktIndex, s.csID, slot.elem)
		if err != nil && !ocsd.DataRespIsFatal(resp) {
			resp = ocsd.RespFatalInvalidData
		}
		s.elemToSend--
		s.sendElemIdx++
	}
	if s.elemToSend == 0 {
		s.resetIndexes()
	}
	return resp
}
