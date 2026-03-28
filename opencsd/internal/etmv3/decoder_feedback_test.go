package etmv3

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestDecodePacketPreservesWaitISyncWithoutOutput(t *testing.T) {
	dec, _ := setupDecFast(&Config{})
	dec.currState = waitISync
	dec.waitISync = true

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktIgnore
	dec.CurrPacketIn = pkt

	resp, pktDone := dec.decodePacket()
	if resp != ocsd.RespCont {
		t.Fatalf("expected RespCont, got %v", resp)
	}
	if !pktDone {
		t.Fatal("expected packet to be complete when no output is generated")
	}
	if dec.currState != waitISync {
		t.Fatalf("expected decoder to remain in waitISync, got %v", dec.currState)
	}
}

func TestOnFlushCommitsPendingElements(t *testing.T) {
	dec, out := setupDecFast(&Config{})
	out.elements = nil
	dec.currState = decodePkts

	elem := dec.outputElemList.NextElem(7)
	elem.SetType(ocsd.GenElemInstrRange)
	dec.outputElemList.PendLastNElem(1)

	resp := dec.OnFlush()
	if resp != ocsd.RespCont {
		t.Fatalf("expected RespCont, got %v", resp)
	}
	if len(out.elements) != 1 {
		t.Fatalf("expected 1 flushed element, got %d", len(out.elements))
	}
	if out.elements[0].ElemType != ocsd.GenElemInstrRange {
		t.Fatalf("expected flushed element to be an instruction range, got %v", out.elements[0].ElemType)
	}
	if dec.currState != decodePkts {
		t.Fatalf("expected flush to return decoder to decodePkts, got %v", dec.currState)
	}
}

func TestProcessBranchAddrContextWithoutException(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	out.elements = nil

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x2400
	pkt.CurrISA = ocsd.ISAThumb2
	pkt.Context.UpdatedC = true
	pkt.Context.CtxtID = 0x44
	pkt.Context.UpdatedV = true
	pkt.Context.VMID = 0x7
	pkt.Context.Updated = true
	pkt.Context.CurrNS = true
	pkt.Context.CurrHyp = true

	resp := dec.PacketDataIn(ocsd.OpData, 2, pkt)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response: %v", resp)
	}

	if len(out.elements) != 1 {
		t.Fatalf("expected one context element, got %d", len(out.elements))
	}
	if out.elements[0].ElemType != ocsd.GenElemPeContext {
		t.Fatalf("expected GenElemPeContext, got %v", out.elements[0].ElemType)
	}
	if out.elements[0].Context.ContextID != 0x44 {
		t.Fatalf("expected ContextID 0x44, got 0x%X", out.elements[0].Context.ContextID)
	}
	if out.elements[0].Context.VMID != 0x7 {
		t.Fatalf("expected VMID 0x7, got 0x%X", out.elements[0].Context.VMID)
	}
	if out.elements[0].Context.SecurityLevel != ocsd.SecNonsecure {
		t.Fatalf("expected non-secure context, got %v", out.elements[0].Context.SecurityLevel)
	}
	if out.elements[0].Context.ExceptionLevel != ocsd.EL2 {
		t.Fatalf("expected EL2 context, got %v", out.elements[0].Context.ExceptionLevel)
	}
	if dec.codeFollower.InstrInfo().ISA != ocsd.ISAThumb2 {
		t.Fatalf("expected code follower ISA to track branch ISA, got %v", dec.codeFollower.InstrInfo().ISA)
	}
}

func TestPendingNaccEmittedAfterCommit(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	out.elements = nil

	elem := dec.outputElemList.NextElem(3)
	elem.SetType(ocsd.GenElemInstrRange)
	dec.outputElemList.PendLastNElem(1)
	dec.pendingNacc = true
	dec.pendingNaccIdx = 3
	dec.pendingNaccAdr = 0x3300
	dec.pendingNaccMem = ocsd.MemSpaceN

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktTrigger

	resp := dec.PacketDataIn(ocsd.OpData, 4, pkt)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response: %v", resp)
	}

	if len(out.elements) != 3 {
		t.Fatalf("expected range, nacc, and trigger elements, got %d", len(out.elements))
	}
	if out.elements[0].ElemType != ocsd.GenElemInstrRange {
		t.Fatalf("expected first element to be GenElemInstrRange, got %v", out.elements[0].ElemType)
	}
	if out.elements[1].ElemType != ocsd.GenElemAddrNacc {
		t.Fatalf("expected second element to be GenElemAddrNacc, got %v", out.elements[1].ElemType)
	}
	if out.elements[1].StartAddr != 0x3300 {
		t.Fatalf("expected NACC address 0x3300, got 0x%X", out.elements[1].StartAddr)
	}
	if out.elements[2].ElemType != ocsd.GenElemEvent {
		t.Fatalf("expected third element to be GenElemEvent, got %v", out.elements[2].ElemType)
	}
	if dec.pendingNacc {
		t.Fatal("expected pending NACC state to be cleared after emission")
	}
}

func TestPendingNaccCancelledWithExceptionCancel(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	out.elements = nil

	elem := dec.outputElemList.NextElem(5)
	elem.SetType(ocsd.GenElemInstrRange)
	dec.outputElemList.PendLastNElem(1)
	dec.pendingNacc = true
	dec.pendingNaccIdx = 5
	dec.pendingNaccAdr = 0x5500
	dec.pendingNaccMem = ocsd.MemSpaceN

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x6600
	pkt.ExceptionCancel = true
	pkt.Exception.Present = true

	resp := dec.PacketDataIn(ocsd.OpData, 6, pkt)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response: %v", resp)
	}
	resp = dec.OnFlush()
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response from flush: %v", resp)
	}

	if len(out.elements) != 0 {
		t.Fatalf("expected cancel to suppress speculative range and NACC, got %v", out.elements)
	}
	if dec.pendingNacc {
		t.Fatal("expected pending NACC state to be cleared by exception cancel")
	}
	if dec.outputElemList.NumElem() != 0 {
		t.Fatalf("expected output list to be empty after cancel, got %d", dec.outputElemList.NumElem())
	}
}

func TestProcessPHdrUsesPacketISA(t *testing.T) {
	dec, out := buildDecInDecodePkts(&Config{})
	out.elements = nil
	dec.codeFollower.SetISA(ocsd.ISAArm)

	phdr := &Packet{}
	phdr.ResetState()
	phdr.Type = PktPHdr
	phdr.CurrISA = ocsd.ISAThumb2
	phdr.PHdrFmt = 1
	phdr.Atom.Num = 1
	phdr.Atom.EnBits = 0x1

	resp := dec.PacketDataIn(ocsd.OpData, 2, phdr)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response: %v", resp)
	}

	trigger := &Packet{}
	trigger.ResetState()
	trigger.Type = PktTrigger
	resp = dec.PacketDataIn(ocsd.OpData, 3, trigger)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("unexpected fatal response: %v", resp)
	}

	for _, elem := range out.elements {
		if elem.ElemType == ocsd.GenElemInstrRange {
			if elem.ISA != ocsd.ISAThumb2 {
				t.Fatalf("expected instruction range ISA %v, got %v", ocsd.ISAThumb2, elem.ISA)
			}
			return
		}
	}
	t.Fatal("expected an instruction range element")
}
