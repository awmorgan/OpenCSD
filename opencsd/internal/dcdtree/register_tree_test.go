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

func (m *fakeManager) CreatePktProc(instID int, config any) interfaces.TrcTypedBase {
	return &fakeDataIn{}
}

func (m *fakeManager) CreatePktDecode(instID int, config any) interfaces.TrcTypedBase {
	return struct{}{}
}

func (m *fakeManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, interfaces.TrcTypedBase, ocsd.Err) {
	return &fakeDataIn{}, struct{}{}, ocsd.OK
}

func (m *fakeManager) ProtocolType() ocsd.TraceProtocol {
	return m.protocol
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

	if err := tree.CreateDecoder(name, int(ocsd.CreateFlgFullDecoder), testConfig{id: 0x23}); err != ocsd.OK {
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

	err := tree.CreateDecoder(name, int(ocsd.CreateFlgFullDecoder), testConfig{id: 0x80})
	if err != ocsd.ErrInvalidID {
		t.Fatalf("expected ErrInvalidID for route ID 0x80, got %v", err)
	}
}
