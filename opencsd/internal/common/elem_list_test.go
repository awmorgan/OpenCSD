package common

import (
	"testing"

	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

type dummySendIf struct {
	sentCount int
}

func (d *dummySendIf) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	d.sentCount++
	return ocsd.RespCont
}

func TestGenElemList(t *testing.T) {
	list := NewGenElemList()
	sendAttached := NewAttachPt[interfaces.TrcGenElemIn]()
	dummy := &dummySendIf{}
	sendAttached.Attach(dummy)

	list.InitSendIf(sendAttached)
	list.InitCSID(10)

	// Test array growth and insertion
	for i := range 5 {
		elem := list.GetNextElem(ocsd.TrcIndex(i))
		elem.SetType(ocsd.GenElemInstrRange)
	}

	if list.GetNumElem() != 5 {
		t.Errorf("Expected 5 elements, got %d", list.GetNumElem())
	}
	if list.GetElemType(0) != ocsd.GenElemInstrRange {
		t.Errorf("Expected GenElemInstrRange, got %v", list.GetElemType(0))
	}

	// Test pending
	list.PendLastNElem(5)
	if list.ElemToSend() || list.NumPendElem() != 5 {
		t.Errorf("Pending logic failed")
	}

	// Send elements (should send 0, leave 5 pending)
	list.SendElements()
	if dummy.sentCount != 0 {
		t.Errorf("Expected 0 sent elements, got %d", dummy.sentCount)
	}

	// Pending logic
	// Cancel pending
	list.CancelPendElem()
	if list.GetNumElem() != 0 || list.NumPendElem() != 0 {
		t.Errorf("Expected 0 elements after cancellation, got %d", list.GetNumElem())
	}

	list.Reset()
	if list.firstIdx != 0 || list.numUsed != 0 {
		t.Errorf("Reset failed")
	}

	list.GetNextElem(0)
	list.PendLastNElem(1)
	list.CommitAllPendElem()
	if list.NumPendElem() != 0 {
		t.Errorf("Commit failed")
	}
}

func TestGenElemStack(t *testing.T) {
	stack := NewGenElemStack()
	sendAttached := NewAttachPt[interfaces.TrcGenElemIn]()
	dummy := &dummySendIf{}
	sendAttached.Attach(dummy)

	stack.InitSendIf(sendAttached)
	stack.InitCSID(11)

	// Add elems to grow array
	for i := range 6 {
		stack.AddElem(ocsd.TrcIndex(i))
	}

	if stack.NumElemToSend() != 7 { // 1 initial + 6 added
		t.Errorf("Expected 7 elements, got %d", stack.NumElemToSend())
	}

	stack.SetCurrElemIdx(10)
	curr := stack.GetCurrElem()
	curr.SetType(ocsd.GenElemEvent)

	stack.AddElemType(11, ocsd.GenElemTimestamp)

	if stack.NumElemToSend() != 8 {
		t.Errorf("Expected 8 elements after AddElemType")
	}

	stack.SendElements()
	if dummy.sentCount != 8 {
		t.Errorf("Expected 8 sent elements, got %d", dummy.sentCount)
	}

	if stack.NumElemToSend() != 1 {
		t.Errorf("Expected reset after send, got %d", stack.NumElemToSend())
	}
}
