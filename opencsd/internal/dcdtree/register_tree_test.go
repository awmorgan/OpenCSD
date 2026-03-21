package dcdtree

import (
	"testing"

	"opencsd/internal/interfaces"
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

type fakeProtocolOnlyManager struct {
	protocol ocsd.TraceProtocol
}

type fakeLegacyDecoderOnlyManager struct {
	protocol ocsd.TraceProtocol
}

type fakeLegacyPktProcOnlyManager struct {
	protocol ocsd.TraceProtocol
}

func (m *fakeManager) CreatePktProc(instID int, config any) any {
	return &fakeDataIn{}
}

func (m *fakeManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	return &fakeDataIn{}, struct{}{}, ocsd.OK
}

func (m *fakeManager) ProtocolType() ocsd.TraceProtocol {
	return m.protocol
}

func (m *fakeProtocolOnlyManager) ProtocolType() ocsd.TraceProtocol {
	return m.protocol
}

func (m *fakeLegacyDecoderOnlyManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	return &fakeDataIn{}, struct{}{}, ocsd.OK
}

func (m *fakeLegacyDecoderOnlyManager) ProtocolType() ocsd.TraceProtocol {
	return m.protocol
}

func (m *fakeLegacyPktProcOnlyManager) CreatePktProc(instID int, config any) any {
	return &fakeDataIn{}
}

func (m *fakeLegacyPktProcOnlyManager) ProtocolType() ocsd.TraceProtocol {
	return m.protocol
}

type fakeTypedManager struct {
	fakeManager
	typedPktProcCalled bool
	typedDecoderCalled bool
}

func (m *fakeTypedManager) CreateTypedPktProc(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	m.typedPktProcCalled = true
	proc := &fakeDataIn{}
	return proc, proc, ocsd.OK
}

func (m *fakeTypedManager) CreateTypedDecoder(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	m.typedDecoderCalled = true
	return &fakeDataIn{}, struct{}{}, ocsd.OK
}

func TestDecoderRegisterCustomProtocolAllocation(t *testing.T) {
	r := NewDecoderRegister()

	if got := r.GetNextCustomProtocolID(); got != ocsd.ProtocolCustom0 {
		t.Fatalf("expected first custom protocol %v, got %v", ocsd.ProtocolCustom0, got)
	}
	if got := r.GetNextCustomProtocolID(); got != ocsd.ProtocolCustom1 {
		t.Fatalf("expected second custom protocol %v, got %v", ocsd.ProtocolCustom1, got)
	}

	r.ReleaseLastCustomProtocolID()
	if got := r.GetNextCustomProtocolID(); got != ocsd.ProtocolCustom1 {
		t.Fatalf("expected released id to be reused (%v), got %v", ocsd.ProtocolCustom1, got)
	}
}

func TestDecoderRegisterTypeMapKeepsFirst(t *testing.T) {
	r := NewDecoderRegister()
	first := &fakeManager{protocol: ocsd.ProtocolSTM}
	second := &fakeManager{protocol: ocsd.ProtocolSTM}

	if err := r.RegisterDecoderTypeByName("FIRST", first); err != ocsd.OK {
		t.Fatalf("register first failed: %v", err)
	}
	if err := r.RegisterDecoderTypeByName("SECOND", second); err != ocsd.OK {
		t.Fatalf("register second failed: %v", err)
	}

	m, err := r.GetDecoderMngrByType(ocsd.ProtocolSTM)
	if err != ocsd.OK {
		t.Fatalf("GetDecoderMngrByType failed: %v", err)
	}
	if m != first {
		t.Fatalf("expected first manager to stay registered for type, got %p want %p", m, first)
	}
}

func TestDecoderRegisterNamedIterationSorted(t *testing.T) {
	r := NewDecoderRegister()
	_ = r.RegisterDecoderTypeByName("ZED", &fakeManager{protocol: ocsd.ProtocolETMV3})
	_ = r.RegisterDecoderTypeByName("ALPHA", &fakeManager{protocol: ocsd.ProtocolPTM})
	_ = r.RegisterDecoderTypeByName("MID", &fakeManager{protocol: ocsd.ProtocolITM})

	names := r.Names()
	want := []string{"ALPHA", "MID", "ZED"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("expected sorted names %v, got %v", want, names)
		}
	}

	n, ok := r.GetFirstNamedDecoder()
	if !ok || n != "ALPHA" {
		t.Fatalf("expected first name ALPHA, got %q, ok=%v", n, ok)
	}
	n, ok = r.GetNextNamedDecoder()
	if !ok || n != "MID" {
		t.Fatalf("expected second name MID, got %q, ok=%v", n, ok)
	}
	n, ok = r.GetNextNamedDecoder()
	if !ok || n != "ZED" {
		t.Fatalf("expected third name ZED, got %q, ok=%v", n, ok)
	}
	if n, ok = r.GetNextNamedDecoder(); ok {
		t.Fatalf("expected end of iteration, got %q", n)
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
	reg := GetDecoderRegister()
	name := "TEST_SINGLE_REMOVE_DECODER"
	if !reg.IsRegisteredDecoder(name) {
		if err := reg.RegisterDecoderTypeByName(name, &fakeManager{protocol: ocsd.ProtocolSTM}); err != ocsd.OK {
			t.Fatalf("register manager failed: %v", err)
		}
	}

	tree := CreateDecodeTree(ocsd.TrcSrcSingle, 0)
	if tree == nil {
		t.Fatal("CreateDecodeTree returned nil")
	}
	defer tree.Destroy()

	if err := tree.CreateFullDecoder(name, testConfig{id: 0x23}); err != ocsd.OK {
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

	firstID, _ := tree.GetFirstElement()
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
	reg := GetDecoderRegister()
	name := "TEST_INVALID_ROUTE_ID"
	if !reg.IsRegisteredDecoder(name) {
		if err := reg.RegisterDecoderTypeByName(name, &fakeManager{protocol: ocsd.ProtocolSTM}); err != ocsd.OK {
			t.Fatalf("register manager failed: %v", err)
		}
	}

	tree := CreateDecodeTree(ocsd.TrcSrcFrameFormatted, ocsd.DfrmtrFrameMemAlign)
	if tree == nil {
		t.Fatal("CreateDecodeTree returned nil")
	}
	defer tree.Destroy()

	err := tree.CreateFullDecoder(name, testConfig{id: 0x80})
	if err != ocsd.ErrInvalidID {
		t.Fatalf("expected ErrInvalidID for route ID 0x80, got %v", err)
	}
}

func TestNewDecodeTreeUsesInjectedRegistry(t *testing.T) {
	const name = "TEST_LOCAL_REGISTRY_ONLY"
	reg := NewDecoderRegister()
	if err := reg.RegisterDecoderTypeByName(name, &fakeManager{protocol: ocsd.ProtocolSTM}); err != ocsd.OK {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if tree == nil {
		t.Fatal("NewDecodeTree returned nil")
	}
	defer tree.Destroy()

	if err := tree.CreateFullDecoder(name, testConfig{id: 0x11}); err != ocsd.OK {
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
	if err := reg.RegisterDecoderTypeByName(name, mgr); err != ocsd.OK {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if err := tree.CreateFullDecoder(name, testConfig{id: 0x12}); err != ocsd.OK {
		t.Fatalf("CreateDecoder failed: %v", err)
	}
	if !mgr.typedDecoderCalled {
		t.Fatal("expected DecodeTree to prefer the typed full-decoder path")
	}

	tree.RemoveDecoder(0x12)
	if err := tree.CreatePacketProcessor(name, testConfig{id: 0x12}); err != ocsd.OK {
		t.Fatalf("CreateDecoder packet-proc path failed: %v", err)
	}
	if !mgr.typedPktProcCalled {
		t.Fatal("expected DecodeTree to prefer the typed packet-processor path")
	}
}

func TestDecodeTreeRejectsManagerWithoutConstructionPath(t *testing.T) {
	const name = "TEST_PROTOCOL_ONLY_MANAGER"
	reg := NewDecoderRegister()
	if err := reg.RegisterDecoderTypeByName(name, &fakeProtocolOnlyManager{protocol: ocsd.ProtocolSTM}); err != ocsd.OK {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	err := tree.CreateFullDecoder(name, testConfig{id: 0x13})
	if err != ocsd.ErrInvalidParamType {
		t.Fatalf("expected ErrInvalidParamType for manager without construction path, got %v", err)
	}
}

func TestDecodeTreeUsesLegacyDecoderOnlyManager(t *testing.T) {
	const name = "TEST_LEGACY_DECODER_ONLY_MANAGER"
	reg := NewDecoderRegister()
	if err := reg.RegisterDecoderTypeByName(name, &fakeLegacyDecoderOnlyManager{protocol: ocsd.ProtocolSTM}); err != ocsd.OK {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if err := tree.CreateFullDecoder(name, testConfig{id: 0x14}); err != ocsd.OK {
		t.Fatalf("CreateDecoder failed: %v", err)
	}
}

func TestDecodeTreeUsesLegacyPktProcOnlyManager(t *testing.T) {
	const name = "TEST_LEGACY_PKTPROC_ONLY_MANAGER"
	reg := NewDecoderRegister()
	if err := reg.RegisterDecoderTypeByName(name, &fakeLegacyPktProcOnlyManager{protocol: ocsd.ProtocolSTM}); err != ocsd.OK {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if err := tree.CreatePacketProcessor(name, testConfig{id: 0x15}); err != ocsd.OK {
		t.Fatalf("CreateDecoder packet-proc path failed: %v", err)
	}
}

func TestDecodeTreeCreateDecoderCompatibilityWrapper(t *testing.T) {
	const name = "TEST_CREATE_DECODER_COMPAT_WRAPPER"
	reg := NewDecoderRegister()
	mgr := &fakeTypedManager{fakeManager: fakeManager{protocol: ocsd.ProtocolSTM}}
	if err := reg.RegisterDecoderTypeByName(name, mgr); err != ocsd.OK {
		t.Fatalf("register manager failed: %v", err)
	}

	tree := NewDecodeTree(ocsd.TrcSrcSingle, 0, reg)
	if err := tree.CreateDecoder(name, int(ocsd.CreateFlgFullDecoder), testConfig{id: 0x16}); err != ocsd.OK {
		t.Fatalf("CreateDecoder full-decoder wrapper failed: %v", err)
	}
	if !mgr.typedDecoderCalled {
		t.Fatal("expected full-decoder wrapper to route to typed decoder path")
	}

	tree.RemoveDecoder(0x16)
	mgr.typedPktProcCalled = false
	if err := tree.CreateDecoder(name, int(ocsd.CreateFlgPacketProc), testConfig{id: 0x16}); err != ocsd.OK {
		t.Fatalf("CreateDecoder packet-proc wrapper failed: %v", err)
	}
	if !mgr.typedPktProcCalled {
		t.Fatal("expected packet-proc wrapper to route to typed pkt-proc path")
	}

	if err := tree.CreateDecoder(name, 0, testConfig{id: 0x17}); err != ocsd.ErrInvalidParamType {
		t.Fatalf("expected ErrInvalidParamType for zero create flags, got %v", err)
	}
}
