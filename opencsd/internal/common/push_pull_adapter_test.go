package common

import (
	"errors"
	"io"
	"testing"
	"time"

	"opencsd/internal/ocsd"
)

func TestPushToPullAdapterEmpty(t *testing.T) {
	adapter := NewPushToPullAdapter()
	adapter.Close()

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

	errCh := make(chan error, 1)
	go func() {
		if err := adapter.TraceElemIn(10, 0x11, first); err != nil {
			errCh <- err
			return
		}
		if err := adapter.TraceElemIn(20, 0x22, second); err != nil {
			errCh <- err
			return
		}
		adapter.Close()
		errCh <- nil
	}()

	gotFirst, err := adapter.Next()
	if err != nil {
		t.Fatalf("Next() first error = %v", err)
	}
	if gotFirst == nil || gotFirst.ElemType != ocsd.GenElemTraceOn {
		t.Fatalf("first element = %#v, want type %v", gotFirst, ocsd.GenElemTraceOn)
	}
	if gotFirst.Index != 10 || gotFirst.TraceID != 0x11 {
		t.Fatalf("first metadata = (%d, %#x), want (10, 0x11)", gotFirst.Index, gotFirst.TraceID)
	}
	adapter.Ack()

	gotSecond, err := adapter.Next()
	if err != nil {
		t.Fatalf("Next() second error = %v", err)
	}
	if gotSecond == nil || gotSecond.ElemType != ocsd.GenElemTimestamp {
		t.Fatalf("second element = %#v, want type %v", gotSecond, ocsd.GenElemTimestamp)
	}
	if gotSecond.Index != 20 || gotSecond.TraceID != 0x22 {
		t.Fatalf("second metadata = (%d, %#x), want (20, 0x22)", gotSecond.Index, gotSecond.TraceID)
	}
	adapter.Ack()

	_, err = adapter.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Next() final error = %v, want io.EOF", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("producer error = %v", err)
	}
}

func TestPushToPullAdapterClonesInput(t *testing.T) {
	adapter := NewPushToPullAdapter()

	input := ocsd.NewTraceElementWithType(ocsd.GenElemCustom)
	input.Timestamp = 42
	input.PtrExtendedData = []byte{1, 2, 3}

	errCh := make(chan error, 1)
	go func() {
		errCh <- adapter.TraceElemIn(0, 0, input)
		adapter.Close()
	}()

	got, err := adapter.Next()
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}

	input.Timestamp = 99
	input.PtrExtendedData[0] = 9

	if got == input {
		t.Fatal("Next() returned original pointer, want cloned element")
	}
	if got.Timestamp != 42 {
		t.Fatalf("Timestamp = %d, want 42", got.Timestamp)
	}
	if len(got.PtrExtendedData) != 3 || got.PtrExtendedData[0] != 1 {
		t.Fatalf("PtrExtendedData = %v, want [1 2 3]", got.PtrExtendedData)
	}
	adapter.Ack()
	if err := <-errCh; err != nil {
		t.Fatalf("TraceElemIn() error = %v", err)
	}
}

func TestPushToPullAdapterNextWaitsForProducer(t *testing.T) {
	adapter := NewPushToPullAdapter()

	resultCh := make(chan error, 1)
	go func() {
		_, err := adapter.Next()
		resultCh <- err
	}()

	select {
	case err := <-resultCh:
		t.Fatalf("Next() returned early with %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	adapter.Close()
	if err := <-resultCh; !errors.Is(err, io.EOF) {
		t.Fatalf("Next() error after close = %v, want io.EOF", err)
	}
}
