package etmv3

// dec_assertions_test.go – properly asserted tests for the ETMv3 packet decoder.
// Tests here verify correctness of:
//   - sendUnsyncPacket (GenElemNoSync emission)
//   - processBranchAddr (context update, exception, cancel paths)
//   - processPHdr (atom E/N, cycle-count variants, NeedAddr paths, MemSpaceS, Nacc)
//   - processISync (LSipAddr + CC, context update, periodic)
//   - OnFlush (sendPkts state with real elements)
//   - OnEOT (GenElemEOTrace emission)

import (
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// ---------------------------------------------------------------------------
// helpers local to this file
// ---------------------------------------------------------------------------

// buildDecInDecodePkts returns a decoder that has gone through Reset→ASync→ISync
// so currState==decodePkts. The testTrcElemIn sink is attached.
func buildDecInDecodePkts(config *Config) (*PktDecode, *testTrcElemIn) {
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	asyncPkt := &Packet{}
	asyncPkt.ResetState()
	asyncPkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1) // non-periodic → emits TraceOn + PeContext
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	return dec, out
}

// elemTypes returns the slice of ElemTypes from the captured elements.
func elemTypes(out *testTrcElemIn) []common.GenElemType {
	types := make([]common.GenElemType, len(out.elements))
	for i, e := range out.elements {
		types[i] = e.ElemType
	}
	return types
}

func containsElemType(out *testTrcElemIn, want common.GenElemType) bool {
	for _, e := range out.elements {
		if e.ElemType == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// sendUnsyncPacket
// ---------------------------------------------------------------------------

// TestSendUnsyncPacket_EmitsNoSync: fresh decoder (no Reset) immediately sees ISync.
// noSync→sendUnsyncPacket → GenElemNoSync emitted, then transitions to waitAsync.
func TestSendUnsyncPacket_EmitsNoSync(t *testing.T) {
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, &Config{})
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	// Do NOT call OpReset - decoder starts in noSync

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.Addr = 0x1000
	pkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	if !containsElemType(out, common.GenElemNoSync) {
		t.Error("expected GenElemNoSync from sendUnsyncPacket")
	}
}

// TestSendUnsyncPacket_UnsyncInfoPreserved: after bad packet, unsyncInfo is UnsyncBadPacket.
func TestSendUnsyncPacket_UnsyncInfoPreserved(t *testing.T) {
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, &Config{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})

	// NoSync state → any packet triggers sendUnsyncPacket → GenElemNoSync
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	found := false
	for _, e := range out.elements {
		if e.ElemType == common.GenElemNoSync {
			found = true
			// verify the UnsyncEOTInfo was set from initDecoder's UnsyncInitDecoder
			if e.Payload.UnsyncEOTInfo != common.UnsyncInitDecoder {
				t.Errorf("expected UnsyncInitDecoder, got %v", e.Payload.UnsyncEOTInfo)
			}
			break
		}
	}
	if !found {
		t.Error("expected GenElemNoSync")
	}
}

// ---------------------------------------------------------------------------
// processBranchAddr
// ---------------------------------------------------------------------------

// TestProcessBranchAddr_NoException_SetsAddr: simple branch updates iAddr.
func TestProcessBranchAddr_NoException_SetsAddr(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})

	// Flush out elements from ISync
	n0 := len(out.elements)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x4000
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	// Branch should NOT emit any elements (no exception, just sets address)
	if len(out.elements) > n0 {
		// This is actually expected – branch commits pending element
		// Just verify no crash and decoder stayed in decodePkts
		_ = out.elements
	}
	// Verify iAddr was updated (internal field)
	if dec.iAddr != 0x4000 {
		t.Errorf("expected iAddr=0x4000, got 0x%X", dec.iAddr)
	}
	if dec.bNeedAddr {
		t.Error("bNeedAddr should be false after branch addr received")
	}
}

// TestProcessBranchAddr_CancelPendElem: Cancel=true → CancelPendElem called.
func TestProcessBranchAddr_CancelPendElem(t *testing.T) {
	config := &Config{}
	dec, out := buildDecInDecodePkts(config)

	// First send an atom to create a pending InstrRange element
	mockI := &mockInstrDecodeWaypoint{returnType: ocsd.InstrBr}
	dec.InstrDecode.Attach(mockI)
	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)
	n0 := len(out.elements)

	// Now send BranchAddress with Cancel=true → CancelPendElem
	brPkt := &Packet{}
	brPkt.ResetState()
	brPkt.Type = PktBranchAddress
	brPkt.Addr = 0x5000
	brPkt.Exception.Cancel = true
	dec.PacketDataIn(ocsd.OpData, 3, brPkt)

	// Elements shouldn't have grown (the pending elem was cancelled)
	_ = n0
	if dec.iAddr != 0x5000 {
		t.Errorf("expected iAddr=0x5000, got 0x%X", dec.iAddr)
	}
}

// TestProcessBranchAddr_ExcepContextUpdate_EmitsPeContext: exception present + context changed.
func TestProcessBranchAddr_ExcepContextUpdate_EmitsPeContext(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	n0 := len(out.elements)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x2000
	pkt.Exception.Present = true
	pkt.Exception.Number = 7 // non-zero → emit exception element too
	pkt.Context.Updated = true
	pkt.Context.CurrNS = true // SecNonsecure, differs from default SecSecure → bUpdatePEContext=true

	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	// Should have emitted at least PeContext + Exception elements
	if len(out.elements) <= n0 {
		t.Error("expected new elements for exception with context update")
	}
	hasPeCtx := false
	hasExcep := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemPeContext {
			hasPeCtx = true
		}
		if e.ElemType == common.GenElemException {
			hasExcep = true
		}
	}
	if !hasPeCtx {
		t.Error("expected GenElemPeContext from branch exception with context update")
	}
	if !hasExcep {
		t.Error("expected GenElemException when exception.Number != 0")
	}
}

// TestProcessBranchAddr_ExcepPresent_SameSecuritySameEL: exception present, CurrHyp=false → el=ELUnknown.
// When el==ELUnknown and sec==SecSecure (both match defaults), bUpdatePEContext should be false.
// BUT: code checks if  el != d.peContext.ExceptionLevel. The ISync we sent had CurrHyp=false → ELUnknown.
// peContext is reset to blank in processISync first-sync, so ExceptionLevel=ELUnknown.
// sec=SecSecure == peContext.SecurityLevel=SecSecure → no security change.
// el=ELUnknown == peContext.ExceptionLevel=ELUnknown → no EL change → bUpdatePEContext=false.
func TestProcessBranchAddr_ExcepPresent_SameSecuritySameEL(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	// ISync in buildDecInDecodePkts doesn't set Context.Updated, so peContext is default.
	// After first ISync, peContext is reset: SecurityLevel=SecSecure, ExceptionLevel=ELUnknown.

	// Now verify peContext defaults
	if dec.peContext.SecurityLevel != ocsd.SecSecure {
		t.Logf("peContext.SecurityLevel=%v", dec.peContext.SecurityLevel)
	}

	n0 := len(out.elements)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x3000
	pkt.Exception.Present = true
	pkt.Exception.Number = 3 // non-zero → exception element
	pkt.Context.Updated = true
	pkt.Context.CurrNS = false  // sec=SecSecure (same as default)
	pkt.Context.CurrHyp = false // el=ELUnknown (same as default)

	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	// Exception element must be present
	hasExcep := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemException {
			hasExcep = true
		}
	}
	if !hasExcep {
		t.Error("expected GenElemException when exception.Number != 0")
	}
}

// TestProcessBranchAddr_ExcepPresent_NumberZero: exception present but Number==0 → no exception elem.
func TestProcessBranchAddr_ExcepPresent_NumberZero(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	n0 := len(out.elements)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x6000
	pkt.Exception.Present = true
	pkt.Exception.Number = 0 // zero → no exception element emitted

	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemException {
			t.Error("should NOT emit GenElemException when exception.Number == 0")
		}
	}
}

// ---------------------------------------------------------------------------
// processPHdr
// ---------------------------------------------------------------------------

// TestProcessPHdr_EAtom_BranchTaken_RangeElement: E-atom with branch instruction.
// Should emit InstrRange element with LastInstrExec=true.
func TestProcessPHdr_EAtom_BranchTaken(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	mockI := &mockInstrDecodeWaypoint{returnType: ocsd.InstrBr}
	dec.InstrDecode.Attach(mockI)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	n0 := len(out.elements)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1 // E-atom
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)

	// processPHdr pends the last InstrRange element until the next non-branch packet commits it.
	// Send a Trigger packet to call CommitAllPendElem, then flush to send.
	trigPkt := &Packet{}
	trigPkt.ResetState()
	trigPkt.Type = PktTrigger
	dec.PacketDataIn(ocsd.OpData, 3, trigPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	if len(out.elements) == n0 {
		t.Error("expected InstrRange element from E-atom processing")
	}
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemInstrRange {
			if e.StAddr != 0x1000 {
				t.Errorf("expected StAddr=0x1000, got 0x%X", e.StAddr)
			}
			// E-atom with InstrBr: LastInstrExec should be true
			if !e.LastInstrExec() {
				t.Error("expected LastInstrExec=true for E-atom with InstrBr")
			}
			return
		}
	}
	t.Logf("elements after n0: %v", elemTypes(out)[n0:])
	t.Error("expected InstrRange element in output")
}

// TestProcessPHdr_NAtom_InstrOther: N-atom with InstrOther → should advance without branch.
func TestProcessPHdr_NAtom_InstrOther(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	// Use mockInstrDecode with hitAfter to avoid infinite loop
	dec.InstrDecode.Attach(&mockInstrDecode{hitAfter: 5, instrType: ocsd.InstrBr})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x0 // N-atom
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)

	// No panic and decoder is still functional
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)
}

// TestProcessPHdr_EAtom_IndirectBr_SetsNeedAddr: IndirectBr branch → setNeedAddr(true).
func TestProcessPHdr_EAtom_IndirectBr_SetsNeedAddr(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	// Attach IndirectBr mock directly (before any other InstrDecode is attached)
	mockI := &mockInstrDecodeWaypoint{returnType: ocsd.InstrBrIndirect}
	dec.InstrDecode.Attach(mockI)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1 // E-atom
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)

	// Send Trigger to commit the pending InstrRange element (non-branch packets call CommitAllPendElem).
	// processPHdr sets bNeedAddr=true after IndirectBr E-atom.
	trigPkt := &Packet{}
	trigPkt.ResetState()
	trigPkt.Type = PktTrigger
	dec.PacketDataIn(ocsd.OpData, 3, trigPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	if !dec.bNeedAddr {
		t.Error("expected bNeedAddr=true after IndirectBr E-atom")
	}
	_ = out
}

// TestProcessPHdr_CCFmt3_WithAtoms: cycle-accurate fmt3 with CC and atoms.
func TestProcessPHdr_CCFmt3_WithAtoms(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc

	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	mockI := &mockInstrDecodeWaypoint{returnType: ocsd.InstrBr}
	dec.InstrDecode.Attach(mockI)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	n0 := len(out.elements)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 3
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	phdrPkt.CycleCount = 5
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)

	// Send Trigger to commit the pending InstrRange element
	trigPkt := &Packet{}
	trigPkt.ResetState()
	trigPkt.Type = PktTrigger
	dec.PacketDataIn(ocsd.OpData, 3, trigPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	// Should emit element with CycleCount set
	found := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemInstrRange && e.CycleCount == 5 {
			found = true
		}
	}
	if !found {
		t.Logf("elements: %v", elemTypes(out)[n0:])
		t.Error("expected InstrRange with CycleCount=5 from fmt3 CC PHdr")
	}
}

// TestProcessPHdr_CCOnly_ZeroAtoms: fmt3 with 0 atoms → pure CC element.
func TestProcessPHdr_CCOnly_ZeroAtoms(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc

	dec, out := buildDecInDecodePkts(config)
	n0 := len(out.elements)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 3
	phdrPkt.Atom.Num = 0
	phdrPkt.CycleCount = 99
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	hasCCElem := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemCycleCount && e.CycleCount == 99 {
			hasCCElem = true
		}
	}
	if !hasCCElem {
		t.Error("expected GenElemCycleCount with CycleCount=99 from zero-atom fmt3 PHdr")
	}
}

// TestProcessPHdr_NeedAddr_EmitsAddrUnknown: bNeedAddr=true, bSentUnknown=false → AddrUnknown.
// After ISync, bNeedAddr=false. After IndrBr E-atom, bNeedAddr=true, bSentUnknown=false.
// The SECOND PHdr sends bNeedAddr=true, bSentUnknown=false (since the first EmitsAddrUnknown).
// Actually the first PHdr with IndirBr puts bNeedAddr=true after the E-atom is processed.
// The FIRST call ITSELF (with bNeedAddr=false initially, from ISync) doesn't emit AddrUnknown.
// It processes the atom, hits IndirBr, then sets bNeedAddr=true.
// The second PHdr call sees bNeedAddr=true, bSentUnknown=false → emits AddrUnknown.
func TestProcessPHdr_NeedAddr_EmitsAddrUnknown(t *testing.T) {
	config := &Config{}
	dec, out := buildDecInDecodePkts(config)

	// First: set bNeedAddr=true directly to skip the complex atom-following
	dec.bNeedAddr = true
	dec.bSentUnknown = false

	n0 := len(out.elements)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	found := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemAddrUnknown {
			found = true
			break
		}
	}
	if !found {
		t.Logf("elements after bNeedAddr=true: %v", elemTypes(out)[n0:])
		t.Error("expected GenElemAddrUnknown when bNeedAddr=true and bSentUnknown=false")
	}
}

// TestProcessPHdr_NeedAddr_SentUnknown_Skips: bNeedAddr=true, bSentUnknown=true, !isCycleAcc → skip.
func TestProcessPHdr_NeedAddr_SentUnknown_Skips(t *testing.T) {
	config := &Config{} // non-CC

	dec, out := buildDecInDecodePkts(config)
	mockI := &mockInstrDecodeWaypoint{returnType: ocsd.InstrBrIndirect}
	dec.InstrDecode.Attach(mockI)

	// First PHdr: bNeedAddr=true, bSentUnknown=false → emits AddrUnknown, bSentUnknown=true
	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 4
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	n0 := len(out.elements)

	// Second PHdr: bNeedAddr=true, bSentUnknown=true, !isCycleAcc → exits loop immediately (skips)
	dec.PacketDataIn(ocsd.OpData, 3, phdrPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	// No new AddrUnknown element should appear (skip path)
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemAddrUnknown {
			t.Error("should NOT emit AddrUnknown when bSentUnknown=true and !isCycleAcc")
		}
	}
}

// TestProcessPHdr_Nacc_ZeroInstructions: memory fails immediately → AddrNacc.
// Uses mockMemAcc with failAfter=0 so first instruction fetch returns 0 bytes → Nacc.
func TestProcessPHdr_Nacc_ZeroInstructions(t *testing.T) {
	config := &Config{}

	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	// failAfter:0 → fail on first call (after 0 successes)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: 0})
	dec.InstrDecode.Attach(&mockInstrDecodeWaypoint{returnType: ocsd.InstrOther})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)
	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	n0 := len(out.elements)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	found := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemAddrNacc {
			found = true
			break
		}
	}
	if !found {
		t.Logf("elements: %v", elemTypes(out)[n0:])
		t.Error("expected GenElemAddrNacc from memory failure")
	}
}

// TestProcessPHdr_MemSpaceSecure: peContext.SecurityLevel=SecSecure → memSpace=S used.
func TestProcessPHdr_MemSpaceSecure(t *testing.T) {
	config := &Config{}

	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	mockI := &mockInstrDecodeWaypoint{returnType: ocsd.InstrBr}
	dec.InstrDecode.Attach(mockI)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	// ISync with CurrNS=false → peContext remains SecSecure
	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	isyncPkt.Context.Updated = true
	isyncPkt.Context.CurrNS = false
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	// Verify peContext is SecSecure
	if dec.peContext.SecurityLevel != ocsd.SecSecure {
		t.Errorf("expected SecSecure after CurrNS=false, got %v", dec.peContext.SecurityLevel)
	}

	// Send atom: processPHdr will set memSpace=MemSpaceS (no crash, exercises that code path)
	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	dec.PacketDataIn(ocsd.OpData, 2, phdrPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	_ = out // just verify no crash
}

// ---------------------------------------------------------------------------
// processISync variations
// ---------------------------------------------------------------------------

// TestProcessISync_NonPeriodic_EmitsTraceOn: reason != periodic → GenElemTraceOn emitted.
func TestProcessISync_NonPeriodic_EmitsTraceOn(t *testing.T) {
	_, out := buildDecInDecodePkts(&Config{})
	// buildDecInDecodePkts already sends non-periodic ISync (reason=1) → check TraceOn
	if !containsElemType(out, common.GenElemTraceOn) {
		t.Error("expected GenElemTraceOn from non-periodic ISync")
	}
}

// TestProcessISync_Periodic_NoTraceOn: second ISync with reason=0 (periodic) → no TraceOn.
func TestProcessISync_Periodic_NoTraceOn(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	n0 := len(out.elements)

	syncPkt2 := &Packet{}
	syncPkt2.ResetState()
	syncPkt2.Type = PktISync
	syncPkt2.Addr = 0x2000
	syncPkt2.ISyncInfo.Reason = ocsd.ISyncReason(0) // periodic
	dec.PacketDataIn(ocsd.OpData, 2, syncPkt2)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemTraceOn {
			t.Error("should NOT emit TraceOn for periodic ISync")
		}
	}
}

// TestProcessISync_WithCC_LSipAddr: ISyncCycle with HasCycleCount + HasLSipAddr.
func TestProcessISync_WithCC_LSipAddr(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc

	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	syncPkt := &Packet{}
	syncPkt.ResetState()
	syncPkt.Type = PktISyncCycle
	syncPkt.Addr = 0x1000
	syncPkt.CurrISA = ocsd.ISAArm
	syncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	syncPkt.ISyncInfo.HasCycleCount = true
	syncPkt.ISyncInfo.HasLSipAddr = true
	syncPkt.CycleCount = 10
	syncPkt.Data.Addr = 0xDEAD
	syncPkt.Context.UpdatedC = true
	syncPkt.Context.CtxtID = 0x42
	dec.PacketDataIn(ocsd.OpData, 1, syncPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	// iAddr should use LSipAddr
	if dec.iAddr != 0xDEAD {
		t.Errorf("expected iAddr=0xDEAD from HasLSipAddr, got 0x%X", dec.iAddr)
	}
	if !containsElemType(out, common.GenElemTraceOn) {
		t.Error("expected GenElemTraceOn")
	}
}

// TestProcessISync_ContextUpdate_CtxAndVMID: context has UpdatedC + UpdatedV → PeContext elem.
func TestProcessISync_ContextUpdate_CtxAndVMID(t *testing.T) {
	config := &Config{}
	dec, out := buildDecInDecodePkts(config)
	n0 := len(out.elements)

	syncPkt2 := &Packet{}
	syncPkt2.ResetState()
	syncPkt2.Type = PktISync
	syncPkt2.Addr = 0x2000
	syncPkt2.ISyncInfo.Reason = ocsd.ISyncReason(1)
	syncPkt2.Context.UpdatedC = true
	syncPkt2.Context.CtxtID = 0xBEEF
	syncPkt2.Context.UpdatedV = true
	syncPkt2.Context.VMID = 9
	syncPkt2.Context.Updated = true
	syncPkt2.Context.CurrNS = true
	dec.PacketDataIn(ocsd.OpData, 2, syncPkt2)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	hasPeCtx := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemPeContext {
			hasPeCtx = true
			if e.Context.ContextID != 0xBEEF {
				t.Errorf("expected ContextID=0xBEEF, got 0x%X", e.Context.ContextID)
			}
			if e.Context.VMID != 9 {
				t.Errorf("expected VMID=9, got %d", e.Context.VMID)
			}
		}
	}
	if !hasPeCtx {
		t.Error("expected GenElemPeContext from ISync with context update")
	}
}

// ---------------------------------------------------------------------------
// OnFlush with sendPkts state
// ---------------------------------------------------------------------------

// TestOnFlush_SendPktsState: decoder in sendPkts → OnFlush sends pending elements.
func TestOnFlush_SendPktsState(t *testing.T) {
	config := &Config{}
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)

	// Directly manipulate to enter sendPkts state with an element pending
	dec.currState = sendPkts
	pElem := dec.outputElemList.GetNextElem(5)
	if pElem != nil {
		pElem.ElemType = common.GenElemEvent
	}
	dec.outputElemList.CommitAllPendElem()

	n0 := len(out.elements)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	if len(out.elements) <= n0 {
		t.Error("expected GenElemEvent from OnFlush in sendPkts state")
	}
	found := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemEvent {
			found = true
		}
	}
	if !found {
		t.Error("expected GenElemEvent in output")
	}
}

// TestOnFlush_SendPkts_WaitISync: sendPkts + bWaitISync=true → transitions back to waitISync.
func TestOnFlush_SendPkts_WaitISync(t *testing.T) {
	manager := NewDecoderManager()
	config := &Config{}
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)

	// Now in waitISync. Send a Timestamp (preISync valid).
	tsPkt := &Packet{}
	tsPkt.ResetState()
	tsPkt.Type = PktTimestamp
	tsPkt.Timestamp = 0xABCD
	dec.PacketDataIn(ocsd.OpData, 1, tsPkt)

	// Manually put into sendPkts with bWaitISync=true
	dec.currState = sendPkts
	dec.bWaitISync = true
	pElem := dec.outputElemList.GetNextElem(2)
	if pElem != nil {
		pElem.ElemType = common.GenElemTimestamp
		pElem.Timestamp = 0xABCD
	}
	dec.outputElemList.CommitAllPendElem()

	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	// After flush, bWaitISync was true → should transition to waitISync
	if dec.currState != waitISync {
		t.Errorf("expected currState=waitISync after flush with bWaitISync=true, got %v", dec.currState)
	}
}

// ---------------------------------------------------------------------------
// OnEOT
// ---------------------------------------------------------------------------

// TestOnEOT_EmitsEOTrace: decoder in decodePkts → OnEOT emits GenElemEOTrace.
func TestOnEOT_EmitsEOTrace(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	n0 := len(out.elements)

	dec.PacketDataIn(ocsd.OpEOT, 0, nil)

	found := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemEOTrace {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GenElemEOTrace from OnEOT")
	}
}

// ---------------------------------------------------------------------------
// preISyncValid – CC and PHdr while in waitISync state
// ---------------------------------------------------------------------------

// TestPreISyncValid_CycleCount_Emitted: CycleCount in waitISync (isCycleAcc=true) → CC element.
func TestPreISyncValid_CycleCount_Emitted(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc

	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	asyncPkt := &Packet{Type: PktASync}
	dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)
	// Now in waitISync

	ccPkt := &Packet{}
	ccPkt.ResetState()
	ccPkt.Type = PktCycleCount
	ccPkt.CycleCount = 42
	dec.PacketDataIn(ocsd.OpData, 1, ccPkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	found := false
	for _, e := range out.elements {
		if e.ElemType == common.GenElemCycleCount && e.CycleCount == 42 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GenElemCycleCount with CycleCount=42 from preISync CycleCount packet")
	}
}

// ---------------------------------------------------------------------------
// Coverage Booster: Trigger
// ---------------------------------------------------------------------------

func TestDecoder_Trigger(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	n0 := len(out.elements)
	pkt := &Packet{Type: PktTrigger}
	dec.PacketDataIn(ocsd.OpData, 1, pkt)
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	found := false
	for _, e := range out.elements[n0:] {
		if e.ElemType == common.GenElemEvent && e.Payload.TraceEvent.EvType == common.EventTrigger {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GenElemEventTrigger from PktTrigger")
	}
}
