package dcdtree

import (
	"context"
	"errors"
	"testing"

	"opencsd/internal/ocsd"
)

type testConfig struct {
	id uint8
}

func (c testConfig) TraceID() uint8 { return c.id }

type fakeDataIn struct{}

func (f *fakeDataIn) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	return uint32(len(dataBlock)), ocsd.RespCont, nil
}

type fakeManager struct {
	protocol ocsd.TraceProtocol
}

func (m *fakeManager) CreateTypedPktProc(instID int, config any) (ocsd.TrcDataIn, any, error) {
	proc := &fakeDataIn{}
	return proc, proc, nil

}

func (m *fakeManager) CreateTypedDecoder(instID int, config any) (ocsd.TrcDataIn, any, error) {
	return &fakeDataIn{}, struct{}{}, nil
}

func (m *fakeManager) ProtocolType() ocsd.TraceProtocol {
	return m.protocol
}

type fakeTypedManager struct {
	fakeManager
	typedPktProcCalled bool
	typedDecoderCalled bool
}

func (m *fakeTypedManager) CreateTypedPktProc(instID int, config any) (ocsd.TrcDataIn, any, error) {
	m.typedPktProcCalled = true
	proc := &fakeDataIn{}
	return proc, proc, nil
}

func (m *fakeTypedManager) CreateTypedDecoder(instID int, config any) (ocsd.TrcDataIn, any, error) {
	m.typedDecoderCalled = true
	return &fakeDataIn{}, struct{}{}, nil
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

	m, err := r.DecoderManagerByTypeStatus(ocsd.ProtocolSTM)
	if err != ocsd.OK {
		t.Fatalf("DecoderManagerByTypeStatus failed: %v", err)
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

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if tree == nil {
		t.Fatal("CreateDecodeTree returned nil")
	}
	defer tree.Destroy()

	if err := tree.CreateFullDecoder(name, testConfig{id: 0x23}); err != nil {
		t.Fatalf("CreateDecoder failed: %v", err)
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

func TestDecodeTreeCreateDecoderRejectsOutOfRangeRouteID(t *testing.T) {
	reg := NewBuiltinDecoderRegister()
	name := "TEST_INVALID_ROUTE_ID"
	if !reg.IsRegisteredDecoder(name) {
		if err := reg.RegisterDecoderManagerByName(name, &fakeManager{protocol: ocsd.ProtocolSTM}); err != nil {
			t.Fatalf("register manager failed: %v", err)
		}
	}

	tree := NewDecodeTree(ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign, reg)
	if tree == nil {
		t.Fatal("CreateDecodeTree returned nil")
	}
	defer tree.Destroy()

	err := tree.CreateFullDecoder(name, testConfig{id: 0x80})
	if got := ocsd.AsErr(err); got != ocsd.ErrInvalidID {
		t.Fatalf("expected ErrInvalidID for route ID 0x80, got %v", err)
	}
}

func TestNewDecodeTreeUsesInjectedRegistry(t *testing.T) {
	const name = "TEST_LOCAL_REGISTRY_ONLY"
	reg := NewDecoderRegister()
	if err := reg.RegisterDecoderManagerByName(name, &fakeManager{protocol: ocsd.ProtocolSTM}); err != nil {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if tree == nil {
		t.Fatal("NewDecodeTree returned nil")
	}
	defer tree.Destroy()

	if err := tree.CreateFullDecoder(name, testConfig{id: 0x11}); err != nil {
		t.Fatalf("CreateDecoder failed using injected registry: %v", err)
	}

	if _, ok := tree.decodeElements[0]; !ok {
		t.Fatal("expected decoder created from injected registry")
	}
}

func TestDecodeTreePrefersTypedManagerPath(t *testing.T) {
	const name = "TEST_TYPED_MANAGER_PATH"
	reg := NewDecoderRegister()
	mgr := &fakeTypedManager{fakeManager: fakeManager{protocol: ocsd.ProtocolSTM}}
	if err := reg.RegisterDecoderManagerByName(name, mgr); err != nil {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if err := tree.CreateFullDecoder(name, testConfig{id: 0x12}); err != nil {
		t.Fatalf("CreateDecoder failed: %v", err)
	}
	if !mgr.typedDecoderCalled {
		t.Fatal("expected DecodeTree to prefer the typed full-decoder path")
	}

	tree.RemoveDecoder(0x12)
	if err := tree.CreatePacketProcessor(name, testConfig{id: 0x12}); err != nil {
		t.Fatalf("CreateDecoder packet-proc path failed: %v", err)
	}
	if !mgr.typedPktProcCalled {
		t.Fatal("expected DecodeTree to prefer the typed packet-processor path")
	}
}

func TestDecodeTreeErrorWrappersExposeSentinels(t *testing.T) {
	reg := NewDecoderRegister()
	if err := reg.Register("STM", &fakeManager{protocol: ocsd.ProtocolSTM}); err != nil {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign, reg)
	if tree == nil {
		t.Fatal("NewDecodeTree returned nil")
	}
	defer tree.Destroy()

	if err := tree.CreateFullDecoderError("STM", testConfig{id: 0x80}); err == nil {
		t.Fatal("expected CreateFullDecoderError to fail for out-of-range route id")
	} else if !errors.Is(err, ErrCreateFullDecoder) {
		t.Fatalf("expected ErrCreateFullDecoder sentinel, got %v", err)
	}

	if err := tree.CreatePacketProcessorError("UNKNOWN_DECODER", testConfig{id: 0x10}); err == nil {
		t.Fatal("expected CreatePacketProcessorError to fail for unknown decoder")
	} else if !errors.Is(err, ErrCreatePacketProcessor) {
		t.Fatalf("expected ErrCreatePacketProcessor sentinel, got %v", err)
	}
}

func TestDecodeTreeTraceDataInContextCancelled(t *testing.T) {
	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, NewBuiltinDecoderRegister())
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
