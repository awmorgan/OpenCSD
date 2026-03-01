package common

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

// ElemPtr pairs a TraceElement pointer with a trace packet index.
type ElemPtr struct {
	PElem     *ocsd.TraceElement
	TrcPktIdx ocsd.TrcIndex
}

// GenElemList implements OcsdGenElemList.
// A circular buffer / ring buffer of TraceElement used to queue items before sending out.
type GenElemList struct {
	elemArray []ElemPtr
	firstIdx  int
	numUsed   int
	numPend   int
	csID      uint8
	sendIf    *AttachPt[interfaces.TrcGenElemIn]
}

// NewGenElemList creates a new list with an initial capacity.
func NewGenElemList() *GenElemList {
	l := &GenElemList{
		elemArray: make([]ElemPtr, 16),
	}
	for i := range l.elemArray {
		l.elemArray[i].PElem = ocsd.NewTraceElement()
	}
	return l
}

func (l *GenElemList) InitSendIf(sendIf *AttachPt[interfaces.TrcGenElemIn]) {
	l.sendIf = sendIf
}

func (l *GenElemList) InitCSID(csID uint8) {
	l.csID = csID
}

func (l *GenElemList) Reset() {
	l.firstIdx = 0
	l.numUsed = 0
	l.numPend = 0
}

func (l *GenElemList) growArray() {
	newSize := len(l.elemArray) * 2
	newArr := make([]ElemPtr, newSize)
	for i := 0; i < newSize; i++ {
		if i < l.numUsed {
			newArr[i] = l.elemArray[l.getAdjustedIdx(l.firstIdx+i)]
		} else {
			newArr[i].PElem = ocsd.NewTraceElement()
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

func (l *GenElemList) GetNextElem(trcPktIdx ocsd.TrcIndex) *ocsd.TraceElement {
	if l.numUsed >= len(l.elemArray) {
		l.growArray()
	}
	idx := l.getAdjustedIdx(l.firstIdx + l.numUsed)
	l.elemArray[idx].TrcPktIdx = trcPktIdx
	l.numUsed++
	return l.elemArray[idx].PElem
}

func (l *GenElemList) GetNumElem() int {
	return l.numUsed
}

func (l *GenElemList) GetElemType(entryN int) ocsd.GenElemType {
	if entryN < l.numUsed {
		idx := l.getAdjustedIdx(l.firstIdx + entryN)
		return l.elemArray[idx].PElem.ElemType
	}
	return ocsd.GenElemUnknown
}

func (l *GenElemList) PendLastNElem(numPend int) {
	if numPend >= l.numUsed {
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
	resp := ocsd.RespCont
	for l.ElemToSend() && ocsd.DataRespIsCont(resp) {
		idx := l.firstIdx
		pPtr := &l.elemArray[idx]

		if l.sendIf != nil && l.sendIf.HasAttachedAndEnabled() {
			resp = l.sendIf.First().TraceElemIn(pPtr.TrcPktIdx, l.csID, pPtr.PElem)
		}

		l.firstIdx = l.getAdjustedIdx(l.firstIdx + 1)
		l.numUsed--
	}
	return resp
}

// GenElemStack implements OcsdGenElemStack.
type GenElemStack struct {
	elemArray   []ElemPtr
	elemToSend  int
	currElemIdx int
	sendElemIdx int
	csID        uint8
	sendIf      *AttachPt[interfaces.TrcGenElemIn]
	isInit      bool
}

// NewGenElemStack creates a new trace element stack.
func NewGenElemStack() *GenElemStack {
	s := &GenElemStack{
		elemArray:  make([]ElemPtr, 4),
		elemToSend: 1,
	}
	for i := range s.elemArray {
		s.elemArray[i].PElem = ocsd.NewTraceElement()
	}
	s.isInit = true
	return s
}

func (s *GenElemStack) InitSendIf(sendIf *AttachPt[interfaces.TrcGenElemIn]) {
	s.sendIf = sendIf
}

func (s *GenElemStack) InitCSID(csID uint8) {
	s.csID = csID
}

func (s *GenElemStack) GetCurrElem() *ocsd.TraceElement {
	return s.elemArray[s.currElemIdx].PElem
}

func (s *GenElemStack) ResetElemStack() ocsd.Err {
	s.elemToSend = 1
	s.currElemIdx = 0
	s.sendElemIdx = 0
	return ocsd.OK
}

func (s *GenElemStack) copyPersistentData(src, dst int) {
	s.elemArray[dst].PElem.CopyPersistentData(s.elemArray[src].PElem)
}

func (s *GenElemStack) growArray() ocsd.Err {
	newSize := len(s.elemArray) * 2
	newArr := make([]ElemPtr, newSize)
	copy(newArr, s.elemArray)
	for i := len(s.elemArray); i < newSize; i++ {
		newArr[i].PElem = ocsd.NewTraceElement()
	}
	s.elemArray = newArr
	return ocsd.OK
}

func (s *GenElemStack) AddElem(trcPktIdx ocsd.TrcIndex) ocsd.Err {
	if s.currElemIdx+1 >= len(s.elemArray) {
		if err := s.growArray(); err != ocsd.OK {
			return err
		}
	}
	s.copyPersistentData(s.currElemIdx, s.currElemIdx+1)
	s.currElemIdx++
	s.elemToSend++
	s.elemArray[s.currElemIdx].TrcPktIdx = trcPktIdx
	return ocsd.OK
}

func (s *GenElemStack) SetCurrElemIdx(trcPktIdx ocsd.TrcIndex) {
	s.elemArray[s.currElemIdx].TrcPktIdx = trcPktIdx
}

func (s *GenElemStack) AddElemType(trcPktIdx ocsd.TrcIndex, elemType ocsd.GenElemType) ocsd.Err {
	err := s.AddElem(trcPktIdx)
	if err == ocsd.OK {
		s.GetCurrElem().SetType(elemType)
	}
	return err
}

func (s *GenElemStack) NumElemToSend() int {
	return s.elemToSend
}

func (s *GenElemStack) SendElements() ocsd.DatapathResp {
	resp := ocsd.RespCont
	for s.elemToSend > 0 && ocsd.DataRespIsCont(resp) {
		pPtr := &s.elemArray[s.sendElemIdx]
		if s.sendIf != nil && s.sendIf.HasAttachedAndEnabled() {
			resp = s.sendIf.First().TraceElemIn(pPtr.TrcPktIdx, s.csID, pPtr.PElem)
		}

		s.elemToSend--
		s.sendElemIdx++
	}
	if s.elemToSend == 0 {
		s.ResetElemStack()
	}
	return resp
}
