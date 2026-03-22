package common

import (
	"testing"

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
	dummy := &dummySendIf{}

	list.SetSendIf(func() ocsd.TrcGenElemIn { return dummy })
	list.SetCSID(10)

	// Test array growth and insertion
	for i := range 5 {
		elem := list.NextElem(ocsd.TrcIndex(i))
		elem.SetType(ocsd.GenElemInstrRange)
	}

	if list.NumElem() != 5 {
		t.Errorf("Expected 5 elements, got %d", list.NumElem())
	}
	if list.ElemType(0) != ocsd.GenElemInstrRange {
		t.Errorf("Expected GenElemInstrRange, got %v", list.ElemType(0))
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
	if list.NumElem() != 0 || list.NumPendElem() != 0 {
		t.Errorf("Expected 0 elements after cancellation, got %d", list.NumElem())
	}

	list.Reset()
	if list.firstIdx != 0 || list.numUsed != 0 {
		t.Errorf("Reset failed")
	}

	list.NextElem(0)
	list.PendLastNElem(1)
	list.CommitAllPendElem()
	if list.NumPendElem() != 0 {
		t.Errorf("Commit failed")
	}
}

func TestGenElemListPendLastPartialWindow(t *testing.T) {
	list := NewGenElemList()
	dummy := &dummySendIf{}

	list.SetSendIf(func() ocsd.TrcGenElemIn { return dummy })
	list.SetCSID(12)

	for i := range 3 {
		elem := list.NextElem(ocsd.TrcIndex(i))
		elem.SetType(ocsd.GenElemInstrRange)
	}

	list.PendLastNElem(1)
	if list.NumPendElem() != 1 {
		t.Fatalf("expected 1 pending element, got %d", list.NumPendElem())
	}
	if !list.ElemToSend() {
		t.Fatal("expected committed elements to remain sendable")
	}

	list.SendElements()
	if dummy.sentCount != 2 {
		t.Fatalf("expected 2 sent elements, got %d", dummy.sentCount)
	}
	if list.NumElem() != 1 || list.NumPendElem() != 1 {
		t.Fatalf("expected 1 pending element left, got num=%d pend=%d", list.NumElem(), list.NumPendElem())
	}

	list.CancelPendElem()
	if list.NumElem() != 0 || list.NumPendElem() != 0 {
		t.Fatalf("expected empty list after cancel, got num=%d pend=%d", list.NumElem(), list.NumPendElem())
	}
	if dummy.sentCount != 2 {
		t.Fatalf("expected cancel to avoid extra sends, got %d", dummy.sentCount)
	}
}

func TestGenElemStack(t *testing.T) {
	stack := NewGenElemStack()
	dummy := &dummySendIf{}

	stack.SetSendIf(func() ocsd.TrcGenElemIn { return dummy })
	stack.SetCSID(11)

	// Add elems to grow array
	for i := range 6 {
		stack.AddElem(ocsd.TrcIndex(i))
	}

	if stack.NumElemToSend() != 6 { // 6 added
		t.Errorf("Expected 6 elements, got %d", stack.NumElemToSend())
	}

	stack.SetCurrElemIdx(10)
	curr := stack.CurrElem()
	curr.SetType(ocsd.GenElemEvent)

	stack.AddElemType(11, ocsd.GenElemTimestamp)

	if stack.NumElemToSend() != 7 {
		t.Errorf("Expected 7 elements after AddElemType")
	}

	stack.SendElements()
	if dummy.sentCount != 7 {
		t.Errorf("Expected 7 sent elements, got %d", dummy.sentCount)
	}

	if stack.NumElemToSend() != 0 {
		t.Errorf("Expected reset after send, got %d", stack.NumElemToSend())
	}
}
