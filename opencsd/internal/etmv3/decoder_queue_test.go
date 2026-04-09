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
