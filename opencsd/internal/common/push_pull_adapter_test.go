package common

import (
	"errors"
	"io"
	"testing"

	"opencsd/internal/ocsd"
)

func TestPushToPullAdapterEmpty(t *testing.T) {
	adapter := NewPushToPullAdapter()

	elem, err := adapter.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Next() error = %v, want io.EOF", err)
	}
	if elem != nil {
		t.Fatalf("Next() element = %#v, want nil", elem)
	}
}

func TestPushToPullAdapterFIFO(t *testing.T) {
	adapter := NewPushToPullAdapter()

	first := ocsd.NewTraceElementWithType(ocsd.GenElemTraceOn)
	second := ocsd.NewTraceElementWithType(ocsd.GenElemTimestamp)

	if err := adapter.TraceElemIn(10, 0x11, first); err != nil {
		t.Fatalf("TraceElemIn(first) error = %v", err)
	}
	if err := adapter.TraceElemIn(20, 0x22, second); err != nil {
		t.Fatalf("TraceElemIn(second) error = %v", err)
	}

	gotFirst, err := adapter.Next()
	if err != nil {
		t.Fatalf("Next() first error = %v", err)
	}
	if gotFirst == nil || gotFirst.ElemType != ocsd.GenElemTraceOn {
		t.Fatalf("first element = %#v, want type %v", gotFirst, ocsd.GenElemTraceOn)
	}

	gotSecond, err := adapter.Next()
	if err != nil {
		t.Fatalf("Next() second error = %v", err)
	}
	if gotSecond == nil || gotSecond.ElemType != ocsd.GenElemTimestamp {
		t.Fatalf("second element = %#v, want type %v", gotSecond, ocsd.GenElemTimestamp)
	}

	_, err = adapter.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Next() final error = %v, want io.EOF", err)
	}
}

func TestPushToPullAdapterClonesInput(t *testing.T) {
	adapter := NewPushToPullAdapter()

	input := ocsd.NewTraceElementWithType(ocsd.GenElemCustom)
	input.Timestamp = 42
	input.PtrExtendedData = []byte{1, 2, 3}

	if err := adapter.TraceElemIn(0, 0, input); err != nil {
		t.Fatalf("TraceElemIn() error = %v", err)
	}

	input.Timestamp = 99
	input.PtrExtendedData[0] = 9

	got, err := adapter.Next()
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if got == input {
		t.Fatal("Next() returned original pointer, want cloned element")
	}
	if got.Timestamp != 42 {
		t.Fatalf("Timestamp = %d, want 42", got.Timestamp)
	}
	if len(got.PtrExtendedData) != 3 || got.PtrExtendedData[0] != 1 {
		t.Fatalf("PtrExtendedData = %v, want [1 2 3]", got.PtrExtendedData)
	}
}
