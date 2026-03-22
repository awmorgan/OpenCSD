package common

import (
	"opencsd/internal/ocsd"
)

type elemSlot struct {
	elem     *ocsd.TraceElement
	pktIndex ocsd.TrcIndex
}

// GenElemList implements OcsdGenElemList.
// A circular buffer / ring buffer of TraceElement used to queue items before sending out.
type GenElemList struct {
	elemArray []elemSlot
	firstIdx  int
	numUsed   int
	numPend   int
	csID      uint8
	sendIf    func() ocsd.TrcGenElemIn
}

// NewGenElemList creates a new list with an initial capacity.
func NewGenElemList() *GenElemList {
	l := &GenElemList{
		elemArray: make([]elemSlot, 16),
	}
	for i := range l.elemArray {
		l.elemArray[i].elem = ocsd.NewTraceElement()
	}
	return l
}

func (l *GenElemList) SetSendIf(sendIf func() ocsd.TrcGenElemIn) {
	l.sendIf = sendIf
}

func (l *GenElemList) SetCSID(csID uint8) {
	l.csID = csID
}

func (l *GenElemList) Reset() {
	l.firstIdx = 0
	l.numUsed = 0
	l.numPend = 0
}

func (l *GenElemList) growArray() {
	newSize := len(l.elemArray) * 2
	newArr := make([]elemSlot, newSize)
	for i := range newSize {
		if i < l.numUsed {
			newArr[i] = l.elemArray[l.getAdjustedIdx(l.firstIdx+i)]
		} else {
			newArr[i].elem = ocsd.NewTraceElement()
		}
	}
	l.elemArray = newArr
	l.firstIdx = 0
}

func (l *GenElemList) getAdjustedIdx(idx int) int {
	if idx >= len(l.elemArray) {
		return idx - len(l.elemArray)
	}
	return idx
}

func (l *GenElemList) NextElem(trcPktIdx ocsd.TrcIndex) *ocsd.TraceElement {
	if l.numUsed >= len(l.elemArray) {
		l.growArray()
	}
	idx := l.getAdjustedIdx(l.firstIdx + l.numUsed)
	l.elemArray[idx].pktIndex = trcPktIdx
	l.numUsed++
	return l.elemArray[idx].elem
}

func (l *GenElemList) NumElem() int {
	return l.numUsed
}

func (l *GenElemList) ElemType(entryN int) ocsd.GenElemType {
	if entryN < l.numUsed {
		idx := l.getAdjustedIdx(l.firstIdx + entryN)
		return l.elemArray[idx].elem.ElemType
	}
	return ocsd.GenElemUnknown
}

func (l *GenElemList) PendLastNElem(numPend int) {
	if numPend > 0 && numPend <= l.numUsed {
		l.numPend = numPend
	}
}

func (l *GenElemList) CommitAllPendElem() {
	l.numPend = 0
}

func (l *GenElemList) CancelPendElem() {
	if l.numPend > 0 {
		l.numUsed -= l.numPend
		l.numPend = 0
	}
}

func (l *GenElemList) NumPendElem() int {
	return l.numPend
}

func (l *GenElemList) ElemToSend() bool {
	return (l.numUsed - l.numPend) > 0
}

func (l *GenElemList) SendElements() ocsd.DatapathResp {
	if l.sendIf == nil {
		return ocsd.RespFatalNotInit
	}
	out := l.sendIf()
	if out == nil {
		return ocsd.RespFatalNotInit
	}
	resp := ocsd.RespCont
	for l.ElemToSend() && ocsd.DataRespIsCont(resp) {
		idx := l.firstIdx
		pPtr := &l.elemArray[idx]
		resp = out.TraceElemIn(pPtr.pktIndex, l.csID, pPtr.elem)
		l.firstIdx = l.getAdjustedIdx(l.firstIdx + 1)
		l.numUsed--
	}
	return resp
}

// GenElemStack implements OcsdGenElemStack.
type GenElemStack struct {
	elemArray   []elemSlot
	elemToSend  int
	currElemIdx int
	sendElemIdx int
	csID        uint8
	sendIf      func() ocsd.TrcGenElemIn
}

// NewGenElemStack creates a new trace element stack.
func NewGenElemStack() *GenElemStack {
	s := &GenElemStack{
		elemArray: make([]elemSlot, 4),
	}
	for i := range s.elemArray {
		s.elemArray[i].elem = ocsd.NewTraceElement()
	}
	return s
}

// isReady checks that stack wiring is complete.
func (s *GenElemStack) isReady() bool {
	return len(s.elemArray) > 0 && s.sendIf != nil
}

func (s *GenElemStack) SetSendIf(sendIf func() ocsd.TrcGenElemIn) {
	s.sendIf = sendIf
}

func (s *GenElemStack) SetCSID(csID uint8) {
	s.csID = csID
}

func (s *GenElemStack) CurrElem() *ocsd.TraceElement {
	return s.elemArray[s.currElemIdx].elem
}

func (s *GenElemStack) ResetElemStack() ocsd.Err {
	if !s.isReady() {
		return ocsd.ErrNotInit
	}
	s.resetIndexes()
	return ocsd.OK
}

func (s *GenElemStack) resetIndexes() {
	if s.currElemIdx > 0 {
		s.copyPersistentData(s.currElemIdx, 0)
	}
	s.currElemIdx = 0
	s.sendElemIdx = 0
	s.elemToSend = 0
}

func (s *GenElemStack) copyPersistentData(src, dst int) {
	s.elemArray[dst].elem.CopyPersistentData(s.elemArray[src].elem)
}

func (s *GenElemStack) growArray() ocsd.Err {
	newSize := len(s.elemArray) + 4
	newArr := make([]elemSlot, newSize)
	copy(newArr, s.elemArray)
	for i := len(s.elemArray); i < newSize; i++ {
		newArr[i].elem = ocsd.NewTraceElement()
	}
	s.elemArray = newArr
	return ocsd.OK
}

func (s *GenElemStack) AddElem(trcPktIdx ocsd.TrcIndex) ocsd.Err {
	if s.currElemIdx+1 == len(s.elemArray) {
		if err := s.growArray(); err != ocsd.OK {
			return err
		}
	}
	if s.elemToSend > 0 {
		s.copyPersistentData(s.currElemIdx, s.currElemIdx+1)
		s.currElemIdx++
	}
	s.elemArray[s.currElemIdx].pktIndex = trcPktIdx
	s.elemToSend++
	return ocsd.OK
}

func (s *GenElemStack) SetCurrElemIdx(trcPktIdx ocsd.TrcIndex) {
	s.elemArray[s.currElemIdx].pktIndex = trcPktIdx
}

func (s *GenElemStack) AddElemType(trcPktIdx ocsd.TrcIndex, elemType ocsd.GenElemType) ocsd.Err {
	err := s.AddElem(trcPktIdx)
	if err == ocsd.OK {
		s.CurrElem().SetType(elemType)
	}
	return err
}

func (s *GenElemStack) NumElemToSend() int {
	return s.elemToSend
}

func (s *GenElemStack) SendElements() ocsd.DatapathResp {
	if !s.isReady() {
		return ocsd.RespFatalNotInit
	}
	out := s.sendIf()
	if out == nil {
		return ocsd.RespFatalNotInit
	}
	resp := ocsd.RespCont
	for s.elemToSend > 0 && ocsd.DataRespIsCont(resp) {
		pPtr := &s.elemArray[s.sendElemIdx]
		resp = out.TraceElemIn(pPtr.pktIndex, s.csID, pPtr.elem)
		s.elemToSend--
		s.sendElemIdx++
	}
	if s.elemToSend == 0 {
		s.resetIndexes()
	}
	return resp
}
