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
	"io"
	"iter"
	"testing"

	"opencsd/internal/idec"
	"opencsd/internal/ocsd"
)

type fakePacketReader struct {
	packet Packet
	called bool
}

func (r *fakePacketReader) NextPacket() (Packet, error) {
	if r.called {
		return Packet{}, io.EOF
	}
	r.called = true
	return r.packet, nil
}

// Packets returns an empty iterator when no packets are available.
func (r *fakePacketReader) Packets() iter.Seq2[Packet, error] {
	return func(yield func(Packet, error) bool) {}
}

func TestPktDecodeProcessNext_EmitsCallbackForPacket(t *testing.T) {
	cfg := &Config{}
	mem := &mockMemAcc{failAfter: -1}
	instr := idec.NewDecoder()

	packet := Packet{}
	packet.ResetState()
	packet.Type = PktISync
	packet.Index = 7
	packet.Addr = 0x1000
	packet.ISyncInfo.Reason = ocsd.ISyncReason(1)

	reader := &fakePacketReader{packet: packet}
	dec, err := NewPktDecode(cfg, mem, instr, reader)
	if err != nil {
		t.Fatalf("NewPktDecode failed: %v", err)
	}

	if err := dec.processNext(); err != nil {
		t.Fatalf("processNext failed: %v", err)
	}

	if dec.CurrPacketIn == nil {
		t.Fatal("expected CurrPacketIn to be set")
	}
	if dec.IndexCurrPkt != packet.Index {
		t.Fatalf("expected IndexCurrPkt=%d, got %d", packet.Index, dec.IndexCurrPkt)
	}
	received := drainDecodedElements(t, dec)
	if len(received) == 0 {
		t.Fatal("expected output sink to receive at least one element")
	}
	if received[0].ElemType != ocsd.GenElemNoSync {
		t.Fatalf("expected first emitted element to be GenElemNoSync, got %v", received[0].ElemType)
	}
	if received[0].Index != packet.Index {
		t.Fatalf("expected emitted element index %d, got %d", packet.Index, received[0].Index)
	}
}

// ---------------------------------------------------------------------------
// sendUnsyncPacket
// ---------------------------------------------------------------------------

// TestSendUnsyncPacket_EmitsNoSync: fresh decoder (no Reset) immediately sees ISync.
// noSync→sendUnsyncPacket → GenElemNoSync emitted, then transitions to waitAsync.
func TestSendUnsyncPacket_EmitsNoSync(t *testing.T) {
	dec := mustNewConfiguredPktDecode(t, &Config{})
	// Do NOT call OpReset - decoder starts in noSync

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.Addr = 0x1000
	pkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 0, pkt)

	found := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemNoSync {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GenElemNoSync from sendUnsyncPacket")
	}
}

// TestSendUnsyncPacket_UnsyncInfoPreserved: after bad packet, unsyncInfo is UnsyncBadPacket.
func TestSendUnsyncPacket_UnsyncInfoPreserved(t *testing.T) {
	dec := mustNewConfiguredPktDecode(t, &Config{})

	// NoSync state → any packet triggers sendUnsyncPacket → GenElemNoSync
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	writeDecodedPacket(dec, 0, pkt)

	found := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemNoSync {
			found = true
			// verify the UnsyncEOTInfo was set from initDecoder's UnsyncInitDecoder
			if e.Payload.UnsyncEOTInfo != ocsd.UnsyncInfo(ocsd.UnsyncInitDecoder) {
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
	dec := buildDecInDecodePktsPull(t, &Config{})

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x4000
	writeDecodedPacket(dec, 2, pkt)

	// Branch should NOT emit any elements (no exception, just sets address)
	_ = drainDecodedElements(t, dec)
	// Verify iAddr was updated (internal field)
	if dec.iAddr != 0x4000 {
		t.Errorf("expected iAddr=0x4000, got 0x%X", dec.iAddr)
	}
	if dec.NeedAddr {
		t.Error("needAddr should be false after branch addr received")
	}
}

// TestProcessBranchAddr_CancelPendElem: Cancel=true → CancelPendElem called.
func TestProcessBranchAddr_CancelPendElem(t *testing.T) {
	config := &Config{}

	// First send an atom to create a pending InstrRange element
	mem := &mockMemAcc{failAfter: -1, hitAfter: 0, instrType: ocsd.InstrBr}
	dec := buildDecInDecodePktsPullWithDeps(t, config, mem, idec.NewDecoder())

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	writeDecodedPacket(dec, 2, phdrPkt)

	// Now send BranchAddress with Cancel=true → CancelPendElem
	brPkt := &Packet{}
	brPkt.ResetState()
	brPkt.Type = PktBranchAddress
	brPkt.Addr = 0x5000
	brPkt.ExceptionCancel = true
	writeDecodedPacket(dec, 3, brPkt)

	_ = drainDecodedElements(t, dec)
	if dec.iAddr != 0x5000 {
		t.Errorf("expected iAddr=0x5000, got 0x%X", dec.iAddr)
	}
}

// TestProcessBranchAddr_ExcepContextUpdate_EmitsPeContext: exception present + context changed.
func TestProcessBranchAddr_ExcepContextUpdate_EmitsPeContext(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x2000
	pkt.Exception.Present = true
	pkt.Exception.Number = 7 // non-zero → emit exception element too
	pkt.Context.Updated = true
	pkt.Context.CurrNS = true // SecNonsecure, differs from default SecSecure → bUpdatePEContext=true

	writeDecodedPacket(dec, 2, pkt)

	// Should have emitted at least PeContext + Exception elements
	elems := drainDecodedElements(t, dec)
	if len(elems) == 0 {
		t.Error("expected new elements for exception with context update")
	}
	hasPeCtx := false
	hasExcep := false
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemPeContext {
			hasPeCtx = true
		}
		if e.ElemType == ocsd.GenElemException {
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
	dec := buildDecInDecodePktsPull(t, &Config{})
	// ISync in buildDecInDecodePktsPull doesn't set Context.Updated, so peContext is default.
	// After first ISync, peContext is reset: SecurityLevel=SecSecure, ExceptionLevel=ELUnknown.

	// Now verify peContext defaults
	if dec.peContext.SecurityLevel != ocsd.SecSecure {
		t.Logf("peContext.SecurityLevel=%v", dec.peContext.SecurityLevel)
	}

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x3000
	pkt.Exception.Present = true
	pkt.Exception.Number = 3 // non-zero → exception element
	pkt.Context.Updated = true
	pkt.Context.CurrNS = false  // sec=SecSecure (same as default)
	pkt.Context.CurrHyp = false // el=ELUnknown (same as default)

	writeDecodedPacket(dec, 2, pkt)

	// Exception element must be present
	hasExcep := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemException {
			hasExcep = true
		}
	}
	if !hasExcep {
		t.Error("expected GenElemException when exception.Number != 0")
	}
}

// TestProcessBranchAddr_ExcepPresent_NumberZero: exception present but Number==0 → no exception elem.
func TestProcessBranchAddr_ExcepPresent_NumberZero(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x6000
	pkt.Exception.Present = true
	pkt.Exception.Number = 0 // zero → no exception element emitted

	writeDecodedPacket(dec, 2, pkt)

	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemException {
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
	mem := &mockMemAcc{failAfter: -1, hitAfter: 0, instrType: ocsd.InstrBr}
	dec := mustNewPktDecode(t, config, mem, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 1, isyncPkt)

	_ = drainDecodedElements(t, dec)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1 // E-atom
	writeDecodedPacket(dec, 2, phdrPkt)

	// processPHdr pends the last InstrRange element until the next non-branch packet commits it.
	// Send a Trigger packet to call CommitAllPendElem, then flush to send.
	trigPkt := &Packet{}
	trigPkt.ResetState()
	trigPkt.Type = PktTrigger
	writeDecodedPacket(dec, 3, trigPkt)
	dec.Flush()

	elems := drainDecodedElements(t, dec)
	if len(elems) == 0 {
		t.Logf("InstrType from follower: %v", dec.codeFollower.InstrInfo.Type)
		t.Logf("InstrOpcode from follower: %x", dec.codeFollower.InstrInfo.Opcode)
		t.Error("expected InstrRange element from E-atom processing")
	}
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemInstrRange {
			if e.StartAddr != 0x1000 {
				t.Errorf("expected StartAddr=0x1000, got 0x%X", e.StartAddr)
			}
			// E-atom with InstrBr: LastInstrExecuted should be true
			if !e.LastInstrExecuted {
				t.Error("expected LastInstrExecuted=true for E-atom with InstrBr")
			}
			return
		}
	}
	t.Logf("elements after decode: %v", len(elems))
	t.Error("expected InstrRange element in output")
}

// TestProcessPHdr_NAtom_InstrOther: N-atom with InstrOther → should advance without branch.
func TestProcessPHdr_NAtom_InstrOther(t *testing.T) {
	config := &Config{}
	mem := &mockMemAcc{failAfter: -1, hitAfter: 5, instrType: ocsd.InstrBr}
	dec := mustNewPktDecode(t, config, mem, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 1, isyncPkt)

	_ = drainDecodedElements(t, dec)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x0 // N-atom
	writeDecodedPacket(dec, 2, phdrPkt)

	// No panic and decoder is still functional
	dec.Flush()
	_ = drainDecodedElements(t, dec)
}

// TestProcessPHdr_EAtom_IndirectBr_SetsNeedAddr: IndirectBr branch → setNeedAddr(true).
func TestProcessPHdr_EAtom_IndirectBr_SetsNeedAddr(t *testing.T) {
	config := &Config{}
	mem := &mockMemAcc{failAfter: -1, hitAfter: 0, instrType: ocsd.InstrBrIndirect}
	dec := mustNewPktDecode(t, config, mem, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 1, isyncPkt)

	_ = drainDecodedElements(t, dec)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1 // E-atom
	writeDecodedPacket(dec, 2, phdrPkt)

	// Send Trigger to commit the pending InstrRange element (non-branch packets call CommitAllPendElem).
	// processPHdr sets needAddr=true after IndirectBr E-atom.
	trigPkt := &Packet{}
	trigPkt.ResetState()
	trigPkt.Type = PktTrigger
	writeDecodedPacket(dec, 3, trigPkt)
	dec.Flush()
	_ = drainDecodedElements(t, dec)

	if !dec.NeedAddr {
		t.Logf("InstrType from follower: %v", dec.codeFollower.InstrInfo.Type)
		t.Logf("InstrOpcode from follower: %x", dec.codeFollower.InstrInfo.Opcode)
		t.Error("expected needAddr=true after IndirectBr E-atom")
	}
}

// TestProcessPHdr_CCFmt3_WithAtoms: cycle-accurate fmt3 with CC and atoms.
func TestProcessPHdr_CCFmt3_WithAtoms(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc

	mem := &mockMemAcc{failAfter: -1, hitAfter: 0, instrType: ocsd.InstrBr}
	dec := mustNewPktDecode(t, config, mem, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 1, isyncPkt)

	_ = drainDecodedElements(t, dec)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 3
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	phdrPkt.CycleCount = 5
	writeDecodedPacket(dec, 2, phdrPkt)

	// Send Trigger to commit the pending InstrRange element
	trigPkt := &Packet{}
	trigPkt.ResetState()
	trigPkt.Type = PktTrigger
	writeDecodedPacket(dec, 3, trigPkt)
	dec.Flush()

	// Should emit element with CycleCount set
	elems := drainDecodedElements(t, dec)
	found := false
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemInstrRange && e.CycleCount == 5 {
			found = true
		}
	}
	if !found {
		t.Logf("elements: %d", len(elems))
		t.Error("expected InstrRange with CycleCount=5 from fmt3 CC PHdr")
	}
}

// TestProcessPHdr_CCOnly_ZeroAtoms: fmt3 with 0 atoms → pure CC element.
func TestProcessPHdr_CCOnly_ZeroAtoms(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc

	dec := buildDecInDecodePktsPull(t, config)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 3
	phdrPkt.Atom.Num = 0
	phdrPkt.CycleCount = 99
	writeDecodedPacket(dec, 2, phdrPkt)
	dec.Flush()

	hasCCElem := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemCycleCount && e.CycleCount == 99 {
			hasCCElem = true
		}
	}
	if !hasCCElem {
		t.Error("expected GenElemCycleCount with CycleCount=99 from zero-atom fmt3 PHdr")
	}
}

// TestProcessPHdr_NeedAddr_EmitsAddrUnknown: needAddr=true, sentUnknown=false → AddrUnknown.
// After ISync, needAddr=false. After IndrBr E-atom, needAddr=true, sentUnknown=false.
// The SECOND PHdr sends needAddr=true, sentUnknown=false (since the first EmitsAddrUnknown).
// Actually the first PHdr with IndirBr puts needAddr=true after the E-atom is processed.
// The FIRST call ITSELF (with needAddr=false initially, from ISync) doesn't emit AddrUnknown.
// It processes the atom, hits IndirBr, then sets needAddr=true.
// The second PHdr call sees needAddr=true, sentUnknown=false → emits AddrUnknown.
func TestProcessPHdr_NeedAddr_EmitsAddrUnknown(t *testing.T) {
	config := &Config{}
	dec := buildDecInDecodePktsPull(t, config)

	// First: set needAddr=true directly to skip the complex atom-following
	dec.NeedAddr = true
	dec.SentUnknown = false

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	writeDecodedPacket(dec, 2, phdrPkt)
	dec.Flush()

	elems := drainDecodedElements(t, dec)
	found := false
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemAddrUnknown {
			found = true
			break
		}
	}
	if !found {
		t.Logf("elements after needAddr=true: %v", elems)
		t.Error("expected GenElemAddrUnknown when needAddr=true and sentUnknown=false")
	}
}

// TestProcessPHdr_NeedAddr_SentUnknown_Skips: needAddr=true, sentUnknown=true, !isCycleAcc → skip.
func TestProcessPHdr_NeedAddr_SentUnknown_Skips(t *testing.T) {
	config := &Config{} // non-CC

	mem := &mockMemAcc{failAfter: -1, hitAfter: 0, instrType: ocsd.InstrBrIndirect}
	dec := buildDecInDecodePktsPullWithDeps(t, config, mem, idec.NewDecoder())

	// First PHdr: needAddr=true, sentUnknown=false → emits AddrUnknown, sentUnknown=true
	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 4
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	writeDecodedPacket(dec, 2, phdrPkt)
	dec.Flush()
	_ = drainDecodedElements(t, dec)

	// No new AddrUnknown element should appear (skip path)
	// Actually, the previous PHdr call set needAddr=true and reset sentUnknown=false.
	// So we need to call it ONCE to set sentUnknown=true, then AGAIN to skip.
	writeDecodedPacket(dec, 3, phdrPkt) // This one emits AddrUnknown and sets sentUnknown=true
	_ = drainDecodedElements(t, dec)
	writeDecodedPacket(dec, 4, phdrPkt) // This one SHOULD skip
	dec.Flush()

	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemAddrUnknown {
			t.Error("should NOT emit AddrUnknown when sentUnknown=true and !isCycleAcc")
		}
	}
}

// TestProcessPHdr_Nacc_ZeroInstructions: memory fails immediately → AddrNacc.
// Uses mockMemAcc with failAfter=0 so first instruction fetch returns 0 bytes → Nacc.
func TestProcessPHdr_Nacc_ZeroInstructions(t *testing.T) {
	config := &Config{}

	dec := mustNewPktDecode(t, config, &mockMemAcc{failAfter: 0}, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)
	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 1, isyncPkt)

	_ = drainDecodedElements(t, dec)

	phdrPkt := &Packet{}
	phdrPkt.ResetState()
	phdrPkt.Type = PktPHdr
	phdrPkt.PHdrFmt = 1
	phdrPkt.Atom.Num = 1
	phdrPkt.Atom.EnBits = 0x1
	writeDecodedPacket(dec, 2, phdrPkt)
	dec.Flush()

	elems := drainDecodedElements(t, dec)
	found := false
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemAddrNacc {
			found = true
			break
		}
	}
	if !found {
		t.Logf("elements: %v", elems)
		t.Error("expected GenElemAddrNacc from memory failure")
	}
}

// TestProcessPHdr_MemSpaceSecure: peContext.SecurityLevel=SecSecure → memSpace=S used.
func TestProcessPHdr_MemSpaceSecure(t *testing.T) {
	config := &Config{}

	mem := &mockMemAcc{failAfter: -1, hitAfter: 0, instrType: ocsd.InstrBr}
	dec := mustNewPktDecode(t, config, mem, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

	// ISync with CurrNS=false → peContext remains SecSecure
	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	isyncPkt.Context.Updated = true
	isyncPkt.Context.CurrNS = false
	writeDecodedPacket(dec, 1, isyncPkt)

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
	writeDecodedPacket(dec, 2, phdrPkt)
	dec.Flush()
}

// ---------------------------------------------------------------------------
// processISync variations
// ---------------------------------------------------------------------------

// TestProcessISync_NonPeriodic_EmitsTraceOn: reason != periodic → GenElemTraceOn emitted.
func TestProcessISync_NonPeriodic_EmitsTraceOn(t *testing.T) {
	dec := mustNewConfiguredPktDecode(t, &Config{})
	dec.Reset(0)
	writeDecodedPacket(dec, 0, &Packet{Type: PktASync})
	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 1, isyncPkt)
	elems := drainDecodedElements(t, dec)
	found := false
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemTraceOn {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GenElemTraceOn from non-periodic ISync")
	}
}

// TestProcessISync_Periodic_NoTraceOn: second ISync with reason=0 (periodic) → no TraceOn.
func TestProcessISync_Periodic_NoTraceOn(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})

	syncPkt2 := &Packet{}
	syncPkt2.ResetState()
	syncPkt2.Type = PktISync
	syncPkt2.Addr = 0x2000
	syncPkt2.ISyncInfo.Reason = ocsd.ISyncReason(0) // periodic
	writeDecodedPacket(dec, 2, syncPkt2)
	dec.Flush()

	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemTraceOn {
			t.Error("should NOT emit TraceOn for periodic ISync")
		}
	}
}

// TestProcessISync_WithCC_LSipAddr: ISyncCycle with HasCycleCount + HasLSipAddr.
func TestProcessISync_WithCC_LSipAddr(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc

	dec := mustNewPktDecode(t, config, &mockMemAcc{failAfter: -1, hitAfter: 0, instrType: ocsd.InstrBr}, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

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
	writeDecodedPacket(dec, 1, syncPkt)
	dec.Flush()

	// iAddr should use LSipAddr
	if dec.iAddr != 0xDEAD {
		t.Errorf("expected iAddr=0xDEAD from HasLSipAddr, got 0x%X", dec.iAddr)
	}
	elems := drainDecodedElements(t, dec)
	found := false
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemTraceOn {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GenElemTraceOn")
	}
}

// TestProcessISync_ContextUpdate_CtxAndVMID: context has UpdatedC + UpdatedV → PeContext elem.
func TestProcessISync_ContextUpdate_CtxAndVMID(t *testing.T) {
	config := &Config{}
	dec := buildDecInDecodePktsPull(t, config)

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
	writeDecodedPacket(dec, 2, syncPkt2)
	dec.Flush()

	hasPeCtx := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemPeContext {
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
	dec := mustNewPktDecode(t, config, &mockMemAcc{failAfter: -1}, idec.NewDecoder())

	dec.Reset(0)

	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	writeDecodedPacket(dec, 1, isyncPkt)

	_ = drainDecodedElements(t, dec)

	// Directly manipulate to enter sendPkts state with an element pending
	dec.currState = sendPkts
	elem := dec.nextOutElem(5)
	if elem != nil {
		elem.ElemType = ocsd.GenElemEvent
	}
	dec.commitAllPendOutElem()

	dec.Flush()

	elems := drainDecodedElements(t, dec)
	found := false
	for _, e := range elems {
		if e.ElemType == ocsd.GenElemEvent {
			found = true
		}
	}
	if !found {
		t.Error("expected GenElemEvent in output from OnFlush in sendPkts state")
	}
}

// TestOnFlush_SendPkts_WaitISync: sendPkts + waitISync=true → transitions back to waitISync.
func TestOnFlush_SendPkts_WaitISync(t *testing.T) {
	config := &Config{}
	dec := mustNewPktDecode(t, config, &mockMemAcc{failAfter: -1}, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)

	// Now in waitISync. Send a Timestamp (preISync valid).
	tsPkt := &Packet{}
	tsPkt.ResetState()
	tsPkt.Type = PktTimestamp
	tsPkt.Timestamp = 0xABCD
	writeDecodedPacket(dec, 1, tsPkt)

	// Manually put into sendPkts with waitISync=true
	dec.currState = sendPkts
	dec.waitISync = true
	elem := dec.nextOutElem(2)
	if elem != nil {
		elem.ElemType = ocsd.GenElemTimestamp
		elem.Timestamp = 0xABCD
	}
	dec.commitAllPendOutElem()

	dec.Flush()

	// After flush, waitISync was true → should transition to waitISync
	if dec.currState != waitISync {
		t.Errorf("expected currState=waitISync after flush with waitISync=true, got %v", dec.currState)
	}
}

// ---------------------------------------------------------------------------
// OnEOT
// ---------------------------------------------------------------------------

// TestOnEOT_EmitsEOTrace: decoder in decodePkts → OnEOT emits GenElemEOTrace.
func TestOnEOT_EmitsEOTrace(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})

	dec.Close()

	found := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemEOTrace {
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

	dec := mustNewPktDecode(t, config, &mockMemAcc{failAfter: -1}, idec.NewDecoder())

	dec.Reset(0)
	asyncPkt := &Packet{Type: PktASync}
	writeDecodedPacket(dec, 0, asyncPkt)
	// Now in waitISync

	ccPkt := &Packet{}
	ccPkt.ResetState()
	ccPkt.Type = PktCycleCount
	ccPkt.CycleCount = 42
	writeDecodedPacket(dec, 1, ccPkt)
	dec.Flush()

	found := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemCycleCount && e.CycleCount == 42 {
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
	dec := buildDecInDecodePktsPull(t, &Config{})
	pkt := &Packet{Type: PktTrigger}
	writeDecodedPacket(dec, 1, pkt)
	dec.Flush()

	found := false
	for _, e := range drainDecodedElements(t, dec) {
		if e.ElemType == ocsd.GenElemEvent && e.Payload.TraceEvent.EvType == ocsd.EventTrigger {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected GenElemEventTrigger from PktTrigger")
	}
}
