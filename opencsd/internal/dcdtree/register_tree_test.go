package dcdtree

import (
	"context"
	"errors"
	"testing"

	"opencsd/internal/ocsd"
)

type fakeDataIn struct{}

func (f *fakeDataIn) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	return uint32(len(dataBlock)), ocsd.RespCont, nil
}

type fakeManager struct {
	protocol ocsd.TraceProtocol
}

func (m *fakeManager) CreatePacketProcessor(instID int, config any) (ocsd.TrcDataProcessor, any, error) {
	proc := &fakeDataIn{}
	return proc, proc, nil

}

func (m *fakeManager) CreateDecoder(instID int, config any) (ocsd.TrcDataProcessor, any, error) {
	return &fakeDataIn{}, struct{}{}, nil
}

func (m *fakeManager) Protocol() ocsd.TraceProtocol {
	return m.protocol
}

func TestDecoderRegisterCustomProtocolAllocation(t *testing.T) {
	r := NewDecoderRegister()

	if got := r.NextCustomProtocolID(); got != ocsd.ProtocolCustom0 {
		t.Fatalf("expected first custom protocol %v, got %v", ocsd.ProtocolCustom0, got)
	}
	if got := r.NextCustomProtocolID(); got != ocsd.ProtocolCustom1 {
		t.Fatalf("expected second custom protocol %v, got %v", ocsd.ProtocolCustom1, got)
	}

	r.ReleaseLastCustomProtocolID()
	if got := r.NextCustomProtocolID(); got != ocsd.ProtocolCustom1 {
		t.Fatalf("expected released id to be reused (%v), got %v", ocsd.ProtocolCustom1, got)
	}
}

func TestDecoderRegisterTypeMapKeepsFirst(t *testing.T) {
	r := NewDecoderRegister()
	first := &fakeManager{protocol: ocsd.ProtocolSTM}
	second := &fakeManager{protocol: ocsd.ProtocolSTM}

	if err := r.RegisterDecoderManagerByName("FIRST", first); err != nil {
		t.Fatalf("register first failed: %v", err)
	}
	if err := r.RegisterDecoderManagerByName("SECOND", second); err != nil {
		t.Fatalf("register second failed: %v", err)
	}

	m, err := r.DecoderManagerByType(ocsd.ProtocolSTM)
	if err != nil {
		t.Fatalf("DecoderManagerByType failed: %v", err)
	}
	if m != first {
		t.Fatalf("expected first manager to stay registered for type, got %p want %p", m, first)
	}
}

func TestDecoderRegisterErrorReturningAPIs(t *testing.T) {
	r := NewDecoderRegister()
	mgr := &fakeManager{protocol: ocsd.ProtocolSTM}

	if err := r.Register("STM", mgr); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	gotByName, err := r.DecoderManagerByName("STM")
	if err != nil {
		t.Fatalf("DecoderManagerByName failed: %v", err)
	}
	if gotByName != mgr {
		t.Fatalf("DecoderManagerByName returned wrong manager: got %p want %p", gotByName, mgr)
	}

	gotByType, err := r.DecoderManagerByType(ocsd.ProtocolSTM)
	if err != nil {
		t.Fatalf("DecoderManagerByType failed: %v", err)
	}
	if gotByType != mgr {
		t.Fatalf("DecoderManagerByType returned wrong manager: got %p want %p", gotByType, mgr)
	}

	if _, err := r.DecoderManagerByName("UNKNOWN"); err == nil {
		t.Fatal("DecoderManagerByName expected error for unknown manager")
	} else if !errors.Is(err, ErrDecoderManagerNotFound) {
		t.Fatalf("expected ErrDecoderManagerNotFound, got %v", err)
	}

	if err := r.Register("STM", mgr); err == nil {
		t.Fatal("expected duplicate register to fail")
	} else if !errors.Is(err, ErrDecoderRegistration) {
		t.Fatalf("expected ErrDecoderRegistration, got %v", err)
	}
}

func TestDecoderRegisterNamedIterationSorted(t *testing.T) {
	r := NewDecoderRegister()
	_ = r.RegisterDecoderManagerByName("ZED", &fakeManager{protocol: ocsd.ProtocolETMV3})
	_ = r.RegisterDecoderManagerByName("ALPHA", &fakeManager{protocol: ocsd.ProtocolPTM})
	_ = r.RegisterDecoderManagerByName("MID", &fakeManager{protocol: ocsd.ProtocolITM})

	names := r.Names()
	want := []string{"ALPHA", "MID", "ZED"}
	if len(names) != len(want) {
		t.Fatalf("expected %d names, got %d", len(want), len(names))
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("expected sorted names %v, got %v", want, names)
		}
	}
}

func TestNewBuiltinDecoderRegisterIncludesBuiltins(t *testing.T) {
	r := NewBuiltinDecoderRegister()
	for _, name := range []string{
		ocsd.BuiltinDcdSTM,
		ocsd.BuiltinDcdITM,
		ocsd.BuiltinDcdPTM,
		ocsd.BuiltinDcdETMV3,
		ocsd.BuiltinDcdETMV4I,
		ocsd.BuiltinDcdETE,
	} {
		if !r.IsRegisteredDecoder(name) {
			t.Fatalf("expected built-in decoder %q to be registered", name)
		}
	}
}

func TestDecodeTreeRemoveDecoderSingleRoutesToZero(t *testing.T) {
	reg := NewBuiltinDecoderRegister()
	name := "TEST_SINGLE_REMOVE_DECODER"
	if !reg.IsRegisteredDecoder(name) {
		if err := reg.RegisterDecoderManagerByName(name, &fakeManager{protocol: ocsd.ProtocolSTM}); err != nil {
			t.Fatalf("register manager failed: %v", err)
		}
	}

	tree, err := NewDecodeTree(ocsd.TrcSrcSingle, 0)
	if err != nil {
		t.Fatalf("NewDecodeTree returned error: %v", err)
	}
	if tree == nil {
		t.Fatal("NewDecodeTree returned nil")
	}
	defer tree.Destroy()

	if err := tree.AddDecoder(0x23, name, ocsd.ProtocolSTM, &fakeDataIn{}, struct{}{}); err != nil {
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

func TestNewDecodeTreeElementHandlesTypedNilManager(t *testing.T) {
	var nilMgr *fakeManager
	var mgr ocsd.DecoderManager = nilMgr

	elem := NewDecodeTreeElement("typed-nil", mgr, struct{}{}, &fakeDataIn{}, true)
	if elem == nil {
		t.Fatal("expected non-nil decode tree element")
	}
	if elem.Protocol != ocsd.ProtocolUnknown {
		t.Fatalf("expected unknown protocol when manager is typed nil, got %v", elem.Protocol)
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
