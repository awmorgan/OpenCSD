package etmv4

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestDecoderOnFlushResolvesPendingState(t *testing.T) {
	d := NewPktDecode(0)
	d.Config = &Config{}
	if err := d.OnProtocolConfig(); err != ocsd.OK {
		t.Fatalf("OnProtocolConfig failed: %v", err)
	}

	d.currState = resolveElem
	resp := d.OnFlush()
	if resp != ocsd.RespCont {
		t.Fatalf("OnFlush resp = %v, want %v", resp, ocsd.RespCont)
	}
	if d.currState != decodePkts {
		t.Fatalf("expected currState to transition to decodePkts, got %v", d.currState)
	}
}

func TestDecoderTSRequiresMarkerWhenConfigured(t *testing.T) {
	d := NewPktDecode(0)
	d.Config = &Config{
		RegIdr0: 0x800000,
		RegIdr1: 0x510, // full version 0x51
	}
	if err := d.OnProtocolConfig(); err != ocsd.OK {
		t.Fatalf("OnProtocolConfig failed: %v", err)
	}

	tsElem := &p0Elem{
		p0Type:    p0TS,
		rootIndex: 1,
		params:    [4]uint32{0x11223344, 0x0, 0x0, 0x0},
	}

	if err := d.processTSCCEventElem(tsElem); err != ocsd.OK {
		t.Fatalf("processTSCCEventElem pre-marker failed: %v", err)
	}
	if got := d.outElem.NumElemToSend(); got != 0 {
		t.Fatalf("expected no timestamp element before TS marker, got %d queued elems", got)
	}

	markerElem := &p0Elem{
		p0Type:    p0Marker,
		rootIndex: 2,
		marker: ocsd.TraceMarkerPayload{
			Type:  ocsd.ElemMarkerTS,
			Value: 0,
		},
	}
	if err := d.processMarkerElem(markerElem); err != ocsd.OK {
		t.Fatalf("processMarkerElem failed: %v", err)
	}
	if !d.eteFirstTSMarker {
		t.Fatalf("expected eteFirstTSMarker to be set after TS marker")
	}

	if err := d.processTSCCEventElem(tsElem); err != ocsd.OK {
		t.Fatalf("processTSCCEventElem post-marker failed: %v", err)
	}
	if got := d.outElem.NumElemToSend(); got != 2 {
		t.Fatalf("expected marker + timestamp queued after TS marker, got %d", got)
	}
}

func TestDecoderDecodePacketFuncRetV8M(t *testing.T) {
	d := NewPktDecode(0)
	d.config = &Config{
		ArchVer:    ocsd.ArchV8,
		CoreProf:   ocsd.ProfileCortexM,
		RegIdr0:    0,
		RegIdr1:    0,
		RegIdr2:    0,
		RegConfigr: 0,
	}
	d.CurrPacketIn = &TracePacket{Type: PktFuncRet}
	d.IndexCurrPkt = 10

	if err := d.decodePacket(); err != ocsd.OK {
		t.Fatalf("decodePacket failed: %v", err)
	}
	if len(d.p0Stack) != 1 {
		t.Fatalf("expected one stacked element for FUNC_RET, got %d", len(d.p0Stack))
	}
	if d.p0Stack[0].p0Type != p0FuncRet {
		t.Fatalf("expected stacked element type p0FuncRet, got %v", d.p0Stack[0].p0Type)
	}
	if !d.p0Stack[0].isP0 {
		t.Fatalf("expected FUNC_RET stack element to be speculative P0")
	}
	if d.currSpecDepth != 1 {
		t.Fatalf("expected currSpecDepth=1 after FUNC_RET, got %d", d.currSpecDepth)
	}
}
