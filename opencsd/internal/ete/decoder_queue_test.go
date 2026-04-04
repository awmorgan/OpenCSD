package ete

import (
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

func TestSequencedDrainFromElementQueue(t *testing.T) {
	d := &PktDecode{}
	elem := ocsd.NewTraceElement()
	elem.SetType(ocsd.GenElemEvent)
	elem.TraceID = 6
	d.queue.Push(common.DrainedElement{Index: 9, Elem: *elem})

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

func TestSinkQueuesToElementQueue(t *testing.T) {
	d := &PktDecode{}
	sink := &pktDecodeSink{decoder: d}
	elem := ocsd.NewTraceElement()
	elem.SetType(ocsd.GenElemTimestamp)

	if err := sink.TraceElemIn(12, 2, elem); err != nil {
		t.Fatalf("TraceElemIn failed: %v", err)
	}
	if len(d.queue) != 1 {
		t.Fatalf("queue len=%d, want 1", len(d.queue))
	}

	_, out, err := d.NextSequenced()
	if err != nil {
		t.Fatalf("NextSequenced failed: %v", err)
	}
	if out.Index != 12 || out.TraceID != 2 || out.ElemType != ocsd.GenElemTimestamp {
		t.Fatalf("out=(idx=%d,trace=%d,type=%v)", out.Index, out.TraceID, out.ElemType)
	}
}
