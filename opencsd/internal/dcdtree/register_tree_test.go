package dcdtree

import (
	"context"
	"errors"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type fakeDataIn struct{}

func (f *fakeDataIn) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	return uint32(len(dataBlock)), ocsd.RespCont, nil
}

type fakeGenElemOut struct{}

func (f *fakeGenElemOut) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) (ocsd.DatapathResp, error) {
	return ocsd.RespCont, nil
}

type fakeMemAccess struct{}

func (f *fakeMemAccess) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	return 0, nil, nil
}

func (f *fakeMemAccess) InvalidateMemAccCache(csTraceID uint8) {}

type fakeInstrDecode struct{}

func (f *fakeInstrDecode) DecodeInstruction(instrInfo *ocsd.InstrInfo) error { return nil }

type fakePipelineWiringHandle struct {
	traceOut  ocsd.GenElemProcessor
	mem       common.TargetMemAccess
	instr     common.InstrDecode
	traceSets int
	memSets   int
	instrSets int
}

func (h *fakePipelineWiringHandle) SetTraceElemOut(out ocsd.GenElemProcessor) {
	h.traceOut = out
	h.traceSets++
}

func (h *fakePipelineWiringHandle) SetMemAccess(mem common.TargetMemAccess) {
	h.mem = mem
	h.memSets++
}

func (h *fakePipelineWiringHandle) SetInstrDecode(instr common.InstrDecode) {
	h.instr = instr
	h.instrSets++
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
	memA := &fakeMemAccess{}
	instrA := &fakeInstrDecode{}

	// Pre-bind dependencies before decoder registration.
	tree.SetGenTraceElemOutI(traceOutA)
	tree.SetMemAccessI(memA)
	tree.SetInstrDecoderI(instrA)

	if err := tree.AddDecoder(0x22, "wired", ocsd.ProtocolETMV4I, &fakeDataIn{}, h); err != nil {
		t.Fatalf("AddDecoder failed: %v", err)
	}

	if h.traceOut != traceOutA || h.mem != memA || h.instr != instrA {
		t.Fatal("expected pre-bound dependencies to be applied on decoder attach")
	}
	if h.traceSets != 1 || h.memSets != 1 || h.instrSets != 1 {
		t.Fatalf("expected single setter call each on attach, got trace=%d mem=%d instr=%d", h.traceSets, h.memSets, h.instrSets)
	}

	// Update dependencies after registration and verify propagation.
	traceOutB := &fakeGenElemOut{}
	memB := &fakeMemAccess{}
	instrB := &fakeInstrDecode{}
	tree.SetGenTraceElemOutI(traceOutB)
	tree.SetMemAccessI(memB)
	tree.SetInstrDecoderI(instrB)

	if h.traceOut != traceOutB || h.mem != memB || h.instr != instrB {
		t.Fatal("expected post-bind dependency updates to reach registered decoder")
	}
	if h.traceSets != 2 || h.memSets != 2 || h.instrSets != 2 {
		t.Fatalf("expected second setter call each on update, got trace=%d mem=%d instr=%d", h.traceSets, h.memSets, h.instrSets)
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

	processed, resp, err := tree.TraceDataInContext(ctx, ocsd.OpData, 0, []byte{0xAA})
	if processed != 0 {
		t.Fatalf("expected zero processed bytes, got %d", processed)
	}
	if resp != ocsd.RespFatalSysErr {
		t.Fatalf("expected RespFatalSysErr, got %v", resp)
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
