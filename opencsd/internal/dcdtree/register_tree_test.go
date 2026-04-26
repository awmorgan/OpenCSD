package dcdtree

import (
	"context"
	"errors"
	"io"
	"iter"
	"slices"
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

type fakeControl struct {
	closeCalls int
	flushCalls int
	resetCalls int
}

func (f *fakeControl) Write(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	return uint32(len(dataBlock)), nil
}
func (f *fakeControl) Close() error {
	f.closeCalls++
	return nil
}
func (f *fakeControl) Flush() error {
	f.flushCalls++
	return nil
}
func (f *fakeControl) Reset(index ocsd.TrcIndex) error {
	f.resetCalls++
	return nil
}

type fakeControlDecoder struct{ fakeControl }

func (f *fakeControlDecoder) Next() (*ocsd.TraceElement, error) {
	return nil, io.EOF
}

func (f *fakeControlDecoder) Elements() iter.Seq2[*ocsd.TraceElement, error] {
	return func(yield func(*ocsd.TraceElement, error) bool) {}
}

type fakeControlProcessor struct{ fakeControl }

type fakeManager struct{ appliedFlags uint32 }

func (f *fakeManager) ApplyFlags(flags uint32) error {
	f.appliedFlags |= flags
	return nil
}

type fakeIterator struct{}

func (f *fakeIterator) Next() (*ocsd.TraceElement, error) {
	return nil, io.EOF
}

// Elements returns an empty iterator, mimicking an empty io.EOF sequence.
func (f *fakeIterator) Elements() iter.Seq2[*ocsd.TraceElement, error] {
	return func(yield func(*ocsd.TraceElement, error) bool) {}
}

func newTestDecodeTree(t *testing.T, srcType ocsd.DcdTreeSrc, formatterCfgFlags uint32) *DecodeTree {
	t.Helper()

	tree, err := NewDecodeTree(srcType, formatterCfgFlags)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	if tree == nil {
		t.Fatal("NewDecodeTree returned nil")
	}
	t.Cleanup(tree.Destroy)
	return tree
}

func TestDecodeTreeRemoveDecoderSingleRoutesToZero(t *testing.T) {
	tree := newTestDecodeTree(t, ocsd.TrcSrcSingle, 0)

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
	for _, id := range []uint8{7, 2, 5} {
		tree.decodeElements[id] = &DecodeTreeElement{}
	}

	firstID, _ := tree.FirstElement()
	if firstID != 2 {
		t.Fatalf("expected first element ID 2, got %d", firstID)
	}

	ids := make([]uint8, 0, len(tree.decodeElements))
	tree.ForEachElement(func(csID uint8, elem *DecodeTreeElement) {
		ids = append(ids, csID)
	})
	if want := []uint8{2, 5, 7}; !slices.Equal(ids, want) {
		t.Fatalf("expected ordered IDs %v, got %v", want, ids)
	}
}

func TestDecodeTreeAddPullDecoderDirectInjection(t *testing.T) {
	tree := newTestDecodeTree(t, ocsd.TrcSrcSingle, 0)

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

	err := tree.AddPullDecoder(0x00, "duplicate", ocsd.ProtocolSTM, pktIn, nil, manager)
	if !errors.Is(err, ocsd.ErrAttachTooMany) {
		t.Fatalf("expected ErrAttachTooMany for duplicate route, got %v", err)
	}
}

func TestDecodeTreeAddPullDecoderCanAttachIteratorAfterProcessor(t *testing.T) {
	tree := newTestDecodeTree(t, ocsd.TrcSrcSingle, 0)

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

func TestDecodeTreeAddPullDecoderCanAttachProcessorAfterIterator(t *testing.T) {
	tree := newTestDecodeTree(t, ocsd.TrcSrcSingle, 0)

	iter := &fakeIterator{}
	if err := tree.AddPullDecoder(0x22, "pull", ocsd.ProtocolETMV4I, nil, iter, nil); err != nil {
		t.Fatalf("initial AddPullDecoder failed: %v", err)
	}

	proc := &fakeDataIn{}
	if err := tree.AddPullDecoder(0x22, "pull", ocsd.ProtocolETMV4I, proc, nil, nil); err != nil {
		t.Fatalf("processor AddPullDecoder failed: %v", err)
	}

	elem := tree.decodeElements[0]
	if elem == nil {
		t.Fatal("expected route 0 element to exist")
	}
	if elem.DataIn != proc {
		t.Fatal("expected processor to be attached on second call")
	}
	if elem.Iterator != iter {
		t.Fatal("expected initial iterator to remain attached")
	}
}

func TestDecodeTreeRoutesControlToProcessorAndDecoder(t *testing.T) {
	tree := newTestDecodeTree(t, ocsd.TrcSrcSingle, 0)

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
	tree := newTestDecodeTree(t, ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign)

	err := tree.AddPullDecoder(0x80, "direct", ocsd.ProtocolSTM, &fakeDataIn{}, nil, &fakeManager{})
	if !errors.Is(err, ocsd.ErrInvalidID) {
		t.Fatalf("expected ErrInvalidID for route ID 0x80, got %v", err)
	}
}

func TestDecodeTreeTraceDataInContextCancelled(t *testing.T) {
	tree := newTestDecodeTree(t, ocsd.TrcSrcSingle, 0)

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
	tree := newTestDecodeTree(t, ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign)

	if tree.frameDeformatter == nil {
		t.Fatal("expected frame deformatter to be initialized")
	}
	if tree.decoderRoot != tree.frameDeformatter {
		t.Fatal("expected decoder root to remain attached to frame deformatter")
	}
}
