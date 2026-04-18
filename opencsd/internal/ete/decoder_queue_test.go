package ete

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestSequencedDrainFromPendingQueue(t *testing.T) {
	d := &PktDecode{}
	elem := ocsd.NewTraceElement()
	elem.SetType(ocsd.GenElemEvent)
	elem.TraceID = 6

	if err := d.traceElemIn(9, 6, elem); err != nil {
		t.Fatalf("traceElemIn failed: %v", err)
	}

	seq, out, err := d.NextSequenced()
	if err != nil {
		t.Fatalf("NextSequenced failed: %v", err)
	}
	if seq == 0 {
		t.Fatalf("expected non-zero sequence")
	}
	if out.Index != 9 || out.TraceID != 6 || out.ElemType != ocsd.GenElemEvent {
		t.Fatalf("out=(idx=%d,trace=%d,type=%v)", out.Index, out.TraceID, out.ElemType)
	}
}
