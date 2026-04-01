package dcdtree

import (
	"context"
	"errors"
	"testing"

	"opencsd/internal/ocsd"
)

type fakeDataIn struct{}

func (f *fakeDataIn) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	return uint32(len(dataBlock)), nil
}

type fakeGenElemOut struct{}

func (f *fakeGenElemOut) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	return nil
}

type fakePipelineWiringHandle struct {
	traceOut  ocsd.GenElemProcessor
	traceSets int
}

func (h *fakePipelineWiringHandle) SetTraceElemOut(out ocsd.GenElemProcessor) {
	h.traceOut = out
	h.traceSets++
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

	if err := tree.AddDecoder(0x23, "TEST_SINGLE", ocsd.ProtocolSTM, &fakeDataIn{}, struct{}{}); err != nil {
		t.Fatalf("AddDecoder failed: %v", err)
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

func TestDecodeTreeAddDecoderDirectInjection(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	defer tree.Destroy()

	pktIn := &fakeDataIn{}
	handle := struct{}{}
	if err := tree.AddDecoder(0x45, "direct", ocsd.ProtocolSTM, pktIn, handle); err != nil {
		t.Fatalf("AddDecoder failed: %v", err)
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
	if elem.DecoderHandle != handle {
		t.Fatal("expected injected decoder handle to be preserved")
	}

	err = tree.AddDecoder(0x00, "duplicate", ocsd.ProtocolSTM, pktIn, handle)
	if !errors.Is(err, ocsd.ErrAttachTooMany) {
		t.Fatalf("expected ErrAttachTooMany for duplicate route, got %v", err)
	}
}

func TestDecodeTreePipelineWiringPropagatesToRegisteredDecoder(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	defer tree.Destroy()

	h := &fakePipelineWiringHandle{}
	traceOutA := &fakeGenElemOut{}

	// Pre-bind dependency before decoder registration.
	tree.SetGenTraceElemOutI(traceOutA)

	if err := tree.AddWiredDecoder(0x22, "wired", ocsd.ProtocolETMV4I, &fakeDataIn{}, h, h); err != nil {
		t.Fatalf("AddDecoder failed: %v", err)
	}

	if h.traceOut != traceOutA {
		t.Fatal("expected pre-bound trace sink to be applied on decoder attach")
	}
	if h.traceSets != 1 {
		t.Fatalf("expected single trace sink setter call on attach, got trace=%d", h.traceSets)
	}

	// Update dependency after registration and verify propagation.
	traceOutB := &fakeGenElemOut{}
	tree.SetGenTraceElemOutI(traceOutB)

	if h.traceOut != traceOutB {
		t.Fatal("expected post-bind trace sink update to reach registered decoder")
	}
	if h.traceSets != 2 {
		t.Fatalf("expected second trace sink setter call on update, got trace=%d", h.traceSets)
	}
}

func TestDecodeTreeAddDecoderRejectsOutOfRangeRouteID(t *testing.T) {
	tree, err := NewDecodeTree(ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	defer tree.Destroy()

	err = tree.AddDecoder(0x80, "direct", ocsd.ProtocolSTM, &fakeDataIn{}, struct{}{})
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

	processed, err := tree.TraceDataInContext(ctx, ocsd.OpData, 0, []byte{0xAA})
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
