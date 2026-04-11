package dcdtree

import (
	"context"
	"errors"
	"io"
	"testing"

	"opencsd/internal/ocsd"
)

type fakeDataIn struct{}

func (f *fakeDataIn) Write(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	return uint32(len(dataBlock)), nil
}
func (f *fakeDataIn) Close() error { return nil }
func (f *fakeDataIn) Flush() error { return nil }
func (f *fakeDataIn) Reset(index ocsd.TrcIndex) error {
	return nil
}

type fakeControlDecoder struct {
	closeCalls int
	flushCalls int
	resetCalls int
}

func (f *fakeControlDecoder) Write(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	return uint32(len(dataBlock)), nil
}
func (f *fakeControlDecoder) Close() error {
	f.closeCalls++
	return nil
}
func (f *fakeControlDecoder) Flush() error {
	f.flushCalls++
	return nil
}
func (f *fakeControlDecoder) Reset(index ocsd.TrcIndex) error {
	f.resetCalls++
	return nil
}
func (f *fakeControlDecoder) Next() (*ocsd.TraceElement, error) {
	return nil, io.EOF
}

type fakeControlProcessor struct {
	closeCalls int
	flushCalls int
	resetCalls int
}

func (f *fakeControlProcessor) Write(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	return uint32(len(dataBlock)), nil
}
func (f *fakeControlProcessor) Close() error {
	f.closeCalls++
	return nil
}
func (f *fakeControlProcessor) Flush() error {
	f.flushCalls++
	return nil
}
func (f *fakeControlProcessor) Reset(index ocsd.TrcIndex) error {
	f.resetCalls++
	return nil
}

type fakeManager struct{ appliedFlags uint32 }

func (f *fakeManager) ApplyFlags(flags uint32) error {
	f.appliedFlags |= flags
	return nil
}

type fakeIterator struct{}

func (f *fakeIterator) Next() (*ocsd.TraceElement, error) {
	return nil, io.EOF
}

func TestDecodeTreeRemoveDecoderSingleRoutesToZero(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	if tree == nil {
		t.Fatal("NewDecodeTree returned nil")
	}
	defer tree.Destroy()

	if err := tree.AddPullDecoder(0x23, "TEST_SINGLE", ocsd.ProtocolSTM, &fakeDataIn{}, nil, &fakeManager{}); err != nil {
		t.Fatalf("AddPullDecoder failed: %v", err)
	}
	if _, ok := tree.decodeElements[0]; !ok {
		t.Fatalf("expected decoder to be routed to ID 0 in single-source mode")
	}

	tree.RemoveDecoder(0x23)
	if len(tree.decodeElements) != 0 {
		t.Fatalf("expected decoder map to be empty after remove, got %d", len(tree.decodeElements))
	}
}

func TestDecodeTreeElementIterationIsOrdered(t *testing.T) {
	tree := &DecodeTree{decodeElements: map[uint8]*DecodeTreeElement{}}
	tree.decodeElements[7] = &DecodeTreeElement{}
	tree.decodeElements[2] = &DecodeTreeElement{}
	tree.decodeElements[5] = &DecodeTreeElement{}

	firstID, _ := tree.FirstElement()
	if firstID != 2 {
		t.Fatalf("expected first element ID 2, got %d", firstID)
	}

	ids := make([]uint8, 0, 3)
	tree.ForEachElement(func(csID uint8, elem *DecodeTreeElement) {
		ids = append(ids, csID)
	})
	want := []uint8{2, 5, 7}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("expected ordered IDs %v, got %v", want, ids)
		}
	}
}

func TestDecodeTreeAddPullDecoderDirectInjection(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	defer tree.Destroy()

	pktIn := &fakeDataIn{}
	manager := &fakeManager{}
	if err := tree.AddPullDecoder(0x45, "direct", ocsd.ProtocolSTM, pktIn, nil, manager); err != nil {
		t.Fatalf("AddPullDecoder failed: %v", err)
	}

	elem, ok := tree.decodeElements[0]
	if !ok {
		t.Fatal("expected direct decoder to be attached at route 0 in single-source mode")
	}
	if elem.Protocol != ocsd.ProtocolSTM {
		t.Fatalf("expected protocol %v, got %v", ocsd.ProtocolSTM, elem.Protocol)
	}
	if elem.DataIn != pktIn {
		t.Fatal("expected injected packet processor to be preserved")
	}
	if elem.FlagApplier != manager {
		t.Fatal("expected injected flag applier to be preserved")
	}

	err = tree.AddPullDecoder(0x00, "duplicate", ocsd.ProtocolSTM, pktIn, nil, manager)
	if !errors.Is(err, ocsd.ErrAttachTooMany) {
		t.Fatalf("expected ErrAttachTooMany for duplicate route, got %v", err)
	}
}

func TestDecodeTreeAddPullDecoderCanAttachIteratorAfterProcessor(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	defer tree.Destroy()

	proc := &fakeDataIn{}
	if err := tree.AddPullDecoder(0x22, "pull", ocsd.ProtocolETMV4I, proc, nil, nil); err != nil {
		t.Fatalf("initial AddPullDecoder failed: %v", err)
	}

	iter := &fakeIterator{}
	if err := tree.AddPullDecoder(0x22, "pull", ocsd.ProtocolETMV4I, nil, iter, nil); err != nil {
		t.Fatalf("iterator AddPullDecoder failed: %v", err)
	}

	elem := tree.decodeElements[0]
	if elem == nil {
		t.Fatal("expected route 0 element to exist")
	}
	if elem.DataIn != proc {
		t.Fatal("expected initial processor to remain attached")
	}
	if elem.Iterator != iter {
		t.Fatal("expected iterator to be attached on second call")
	}
}

func TestDecodeTreeRoutesControlToProcessorAndDecoder(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	defer tree.Destroy()

	proc := &fakeControlProcessor{}
	dec := &fakeControlDecoder{}

	if err := tree.AddPullDecoder(0x22, "pull", ocsd.ProtocolETMV4I, proc, nil, nil); err != nil {
		t.Fatalf("initial AddPullDecoder failed: %v", err)
	}
	if err := tree.AddPullDecoder(0x22, "pull", ocsd.ProtocolETMV4I, nil, dec, nil); err != nil {
		t.Fatalf("iterator AddPullDecoder failed: %v", err)
	}

	if err := tree.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if err := tree.Reset(123); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if proc.flushCalls != 1 || proc.resetCalls != 1 || proc.closeCalls != 1 {
		t.Fatalf("expected processor control calls 1/1/1, got flush=%d reset=%d close=%d", proc.flushCalls, proc.resetCalls, proc.closeCalls)
	}
	if dec.flushCalls != 1 || dec.resetCalls != 1 || dec.closeCalls != 1 {
		t.Fatalf("expected decoder control calls 1/1/1, got flush=%d reset=%d close=%d", dec.flushCalls, dec.resetCalls, dec.closeCalls)
	}
}

func TestDecodeTreeAddPullDecoderRejectsOutOfRangeRouteID(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	defer tree.Destroy()

	err = tree.AddPullDecoder(0x80, "direct", ocsd.ProtocolSTM, &fakeDataIn{}, nil, &fakeManager{})
	if !errors.Is(err, ocsd.ErrInvalidID) {
		t.Fatalf("expected ErrInvalidID for route ID 0x80, got %v", err)
	}
}

func TestDecodeTreeTraceDataInContextCancelled(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	if tree == nil {
		t.Fatal("NewDefaultDecodeTree returned nil")
	}
	defer tree.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	processed, err := tree.WriteContext(ctx, 0, []byte{0xAA})
	if processed != 0 {
		t.Fatalf("expected zero processed bytes, got %d", processed)
	}
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestNewDecodeTreeFailsOnInvalidFrameFormatterConfig(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcFrameFormatted, 0)
	if err == nil {
		t.Fatal("expected constructor to fail for invalid formatter config")
	}
	if !errors.Is(err, ErrCreateDecodeTree) {
		t.Fatalf("expected ErrCreateDecodeTree, got %v", err)
	}
	if tree != nil {
		t.Fatal("expected nil tree when formatter configuration fails")
	}
}

func TestNewDecodeTreeBuildsFrameTreeOnValidFormatterConfig(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign)
	if err != nil {
		t.Fatalf("expected constructor success, got %v", err)
	}
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	defer tree.Destroy()

	if tree.frameDeformatter == nil {
		t.Fatal("expected frame deformatter to be initialized")
	}
	if tree.decoderRoot != tree.frameDeformatter {
		t.Fatal("expected decoder root to remain attached to frame deformatter")
	}
}
