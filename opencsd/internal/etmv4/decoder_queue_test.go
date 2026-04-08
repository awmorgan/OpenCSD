package etmv4

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestDecoderQueueFlushOrder(t *testing.T) {
	d, err := NewPktDecode(&Config{})
	if err != nil {
		t.Fatalf("NewPktDecode failed: %v", err)
	}

	if err := d.outElem.AddElemType(3, ocsd.GenElemEvent); err != nil {
		t.Fatalf("AddElemType failed: %v", err)
	}

	if err := d.outElem.AddElemType(4, ocsd.GenElemTimestamp); err != nil {
		t.Fatalf("AddElemType failed: %v", err)
	}

	d.flushOutputElements()

	idx, _, elem, err := d.NextElement()
	if err != nil {
		t.Fatalf("NextElement first failed: %v", err)
	}
	if idx != 3 || elem.ElemType != ocsd.GenElemEvent {
		t.Fatalf("first out=(idx=%d,type=%v), want (3,%v)", idx, elem.ElemType, ocsd.GenElemEvent)
	}

	idx, _, elem, err = d.NextElement()
	if err != nil {
		t.Fatalf("NextElement second failed: %v", err)
	}
	if idx != 4 || elem.ElemType != ocsd.GenElemTimestamp {
		t.Fatalf("second out=(idx=%d,type=%v), want (4,%v)", idx, elem.ElemType, ocsd.GenElemTimestamp)
	}
}
