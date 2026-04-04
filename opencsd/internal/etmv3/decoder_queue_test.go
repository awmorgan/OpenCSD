package etmv3

import (
	"errors"
	"io"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

func TestDecoderQueueFlushFromQueue(t *testing.T) {
	dec := mustNewConfiguredPktDecode(t, &Config{})

	elem := ocsd.NewTraceElement()
	elem.SetType(ocsd.GenElemEvent)
	dec.queue.Push(common.DrainedElement{Index: 7, Elem: *elem})
	dec.flushOutputQueue()

	idx, traceID, out, err := dec.NextElement()
	if err != nil {
		t.Fatalf("NextElement failed: %v", err)
	}
	if idx != 7 {
		t.Fatalf("index=%d, want 7", idx)
	}
	if traceID != dec.csID {
		t.Fatalf("traceID=%d, want %d", traceID, dec.csID)
	}
	if out.ElemType != ocsd.GenElemEvent {
		t.Fatalf("elem type=%v, want %v", out.ElemType, ocsd.GenElemEvent)
	}

	_, _, _, err = dec.NextElement()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after draining queue, got %v", err)
	}
}

func TestDecoderQueueFlushFromLegacyList(t *testing.T) {
	dec := mustNewConfiguredPktDecode(t, &Config{})

	elem := dec.outputElemList.NextElem(11)
	elem.SetType(ocsd.GenElemTimestamp)
	dec.outputElemList.CommitAllPendElem()

	dec.flushOutputElements()

	idx, _, out, err := dec.NextElement()
	if err != nil {
		t.Fatalf("NextElement failed: %v", err)
	}
	if idx != 11 {
		t.Fatalf("index=%d, want 11", idx)
	}
	if out.ElemType != ocsd.GenElemTimestamp {
		t.Fatalf("elem type=%v, want %v", out.ElemType, ocsd.GenElemTimestamp)
	}
}
