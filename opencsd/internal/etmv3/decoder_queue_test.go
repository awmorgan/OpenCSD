package etmv3

import (
	"opencsd/internal/ocsd"
	"testing"
)

func TestDecoderQueueFlushFromLegacyList(t *testing.T) {
	dec := mustNewConfiguredPktDecode(t, &Config{})

	elem := dec.nextOutElem(11)
	elem.SetType(ocsd.GenElemTimestamp)
	dec.commitAllPendOutElem()

	dec.flushOutputElements()

	if len(dec.pendingElements) != 1 {
		t.Fatalf("expected 1 flushed element, got %d", len(dec.pendingElements))
	}
	out := dec.pendingElements[0].elem
	out.Index = dec.pendingElements[0].index
	out.TraceID = dec.pendingElements[0].traceID
	if out.Index != 11 {
		t.Fatalf("index=%d, want 11", out.Index)
	}
	if out.ElemType != ocsd.GenElemTimestamp {
		t.Fatalf("elem type=%v, want %v", out.ElemType, ocsd.GenElemTimestamp)
	}
}
