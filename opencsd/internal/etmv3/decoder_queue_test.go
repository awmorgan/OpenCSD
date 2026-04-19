package etmv3

import (
	"opencsd/internal/ocsd"
	"testing"
)

func TestDecoderQueueFlushFromLegacyList(t *testing.T) {
	dec := mustNewConfiguredPktDecode(t, &Config{})

	elem, err := dec.nextOutElem(11)
	if err != nil {
		t.Fatalf("nextOutElem failed: %v", err)
	}
	elem.SetType(ocsd.GenElemTimestamp)
	if err := dec.commitAllPendOutElem(); err != nil {
		t.Fatalf("commitAllPendOutElem failed: %v", err)
	}

	dec.flushOutputElements()

	if len(dec.pendingElements) != 1 {
		t.Fatalf("expected 1 flushed element, got %d", len(dec.pendingElements))
	}
	out := dec.pendingElements[0].elem
	out.Index = dec.pendingElements[0].index
	if out.Index != 11 {
		t.Fatalf("index=%d, want 11", out.Index)
	}
	if out.ElemType != ocsd.GenElemTimestamp {
		t.Fatalf("elem type=%v, want %v", out.ElemType, ocsd.GenElemTimestamp)
	}
}
