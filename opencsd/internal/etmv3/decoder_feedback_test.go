package etmv3

import (
	"testing"

	"opencsd/internal/idec"
	"opencsd/internal/ocsd"
)

func buildDecInDecodePktsPull(t *testing.T, config *Config) *PktDecode {
	t.Helper()
	dec, err := NewConfiguredPktDecode(0, config, &mockMemAcc{failAfter: -1}, idec.NewDecoder())
	if err != nil {
		t.Fatalf("NewConfiguredPktDecode failed: %v", err)
	}

	dec.Reset(0)

	asyncPkt := &Packet{}
	asyncPkt.ResetState()
	asyncPkt.Type = PktASync
	dec.Write(0, asyncPkt)

	isyncPkt := &Packet{}
	isyncPkt.ResetState()
	isyncPkt.Type = PktISync
	isyncPkt.Addr = 0x1000
	isyncPkt.CurrISA = ocsd.ISAArm
	isyncPkt.ISyncInfo.Reason = ocsd.ISyncReason(1)
	dec.Write(1, isyncPkt)

	_ = drainDecodedElements(t, dec)
	return dec
}

func TestDecodePacketPreservesWaitISyncWithoutOutput(t *testing.T) {
	dec := setupDecFast(&Config{})
	dec.currState = waitISync
	dec.waitISync = true

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktIgnore
	dec.CurrPacketIn = pkt

	err, pktDone := dec.decodePacket()
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if !pktDone {
		t.Fatal("expected packet to be complete when no output is generated")
	}
	if dec.currState != waitISync {
		t.Fatalf("expected decoder to remain in waitISync, got %v", dec.currState)
	}
}

func TestOnFlushCommitsPendingElements(t *testing.T) {
	dec := setupDecFast(&Config{})
	dec.currState = decodePkts

	elem := dec.nextOutElem(7)
	elem.SetType(ocsd.GenElemInstrRange)
	dec.pendLastNOutElem(1)

	err := dec.OnFlush()
	if err != nil {
		t.Fatalf("expected err nil, got %v", err)
	}
	elems := drainDecodedElements(t, dec)
	if len(elems) != 1 {
		t.Fatalf("expected 1 flushed element, got %d", len(elems))
	}
	if elems[0].ElemType != ocsd.GenElemInstrRange {
		t.Fatalf("expected flushed element to be an instruction range, got %v", elems[0].ElemType)
	}
	if dec.currState != decodePkts {
		t.Fatalf("expected flush to return decoder to decodePkts, got %v", dec.currState)
	}
}

func TestProcessBranchAddrContextWithoutException(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})

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

	err := dec.Write(2, pkt)
	if err != nil {
		t.Fatalf("unexpected fatal response: %v", err)
	}

	elems := drainDecodedElements(t, dec)
	if len(elems) != 1 {
		t.Fatalf("expected one context element, got %d", len(elems))
	}
	if elems[0].ElemType != ocsd.GenElemPeContext {
		t.Fatalf("expected GenElemPeContext, got %v", elems[0].ElemType)
	}
	if elems[0].Context.ContextID != 0x44 {
		t.Fatalf("expected ContextID 0x44, got 0x%X", elems[0].Context.ContextID)
	}
	if elems[0].Context.VMID != 0x7 {
		t.Fatalf("expected VMID 0x7, got 0x%X", elems[0].Context.VMID)
	}
	if elems[0].Context.SecurityLevel != ocsd.SecNonsecure {
		t.Fatalf("expected non-secure context, got %v", elems[0].Context.SecurityLevel)
	}
	if elems[0].Context.ExceptionLevel != ocsd.EL2 {
		t.Fatalf("expected EL2 context, got %v", elems[0].Context.ExceptionLevel)
	}
	if dec.codeFollower.InstrInfo.ISA != ocsd.ISAThumb2 {
		t.Fatalf("expected code follower ISA to track branch ISA, got %v", dec.codeFollower.InstrInfo.ISA)
	}
}

func TestPendingNaccEmittedAfterCommit(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})

	elem := dec.nextOutElem(3)
	elem.SetType(ocsd.GenElemInstrRange)
	dec.pendLastNOutElem(1)
	dec.ctx.pendingNacc = true
	dec.ctx.pendingNaccIdx = 3
	dec.ctx.pendingNaccAdr = 0x3300
	dec.ctx.pendingNaccMem = ocsd.MemSpaceN

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktTrigger

	err := dec.Write(4, pkt)
	if err != nil {
		t.Fatalf("unexpected fatal response: %v", err)
	}

	elems := drainDecodedElements(t, dec)
	if len(elems) != 3 {
		t.Fatalf("expected range, nacc, and trigger elements, got %d", len(elems))
	}
	if elems[0].ElemType != ocsd.GenElemInstrRange {
		t.Fatalf("expected first element to be GenElemInstrRange, got %v", elems[0].ElemType)
	}
	if elems[1].ElemType != ocsd.GenElemAddrNacc {
		t.Fatalf("expected second element to be GenElemAddrNacc, got %v", elems[1].ElemType)
	}
	if elems[1].StartAddr != 0x3300 {
		t.Fatalf("expected NACC address 0x3300, got 0x%X", elems[1].StartAddr)
	}
	if elems[2].ElemType != ocsd.GenElemEvent {
		t.Fatalf("expected third element to be GenElemEvent, got %v", elems[2].ElemType)
	}
	if dec.ctx.pendingNacc {
		t.Fatal("expected pending NACC state to be cleared after emission")
	}
}

func TestPendingNaccCancelledWithExceptionCancel(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})

	elem := dec.nextOutElem(5)
	elem.SetType(ocsd.GenElemInstrRange)
	dec.pendLastNOutElem(1)
	dec.ctx.pendingNacc = true
	dec.ctx.pendingNaccIdx = 5
	dec.ctx.pendingNaccAdr = 0x5500
	dec.ctx.pendingNaccMem = ocsd.MemSpaceN

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Addr = 0x6600
	pkt.ExceptionCancel = true
	pkt.Exception.Present = true

	err := dec.Write(6, pkt)
	if err != nil {
		t.Fatalf("unexpected fatal response: %v", err)
	}
	err = dec.OnFlush()
	if err != nil {
		t.Fatalf("unexpected fatal response from flush: %v", err)
	}

	elems := drainDecodedElements(t, dec)
	if len(elems) != 0 {
		t.Fatalf("expected cancel to suppress speculative range and NACC, got %v", elems)
	}
	if dec.ctx.pendingNacc {
		t.Fatal("expected pending NACC state to be cleared by exception cancel")
	}
	if dec.numOutElem() != 0 {
		t.Fatalf("expected output list to be empty after cancel, got %d", dec.numOutElem())
	}
}

func TestProcessPHdrUsesPacketISA(t *testing.T) {
	dec := buildDecInDecodePktsPull(t, &Config{})
	dec.codeFollower.Isa = ocsd.ISAArm
	dec.codeFollower.InstrInfo.ISA = ocsd.ISAArm

	phdr := &Packet{}
	phdr.ResetState()
	phdr.Type = PktPHdr
	phdr.CurrISA = ocsd.ISAThumb2
	phdr.PHdrFmt = 1
	phdr.Atom.Num = 1
	phdr.Atom.EnBits = 0x1

	err := dec.Write(2, phdr)
	if err != nil {
		t.Fatalf("unexpected fatal response: %v", err)
	}

	trigger := &Packet{}
	trigger.ResetState()
	trigger.Type = PktTrigger
	err = dec.Write(3, trigger)
	if err != nil {
		t.Fatalf("unexpected fatal response: %v", err)
	}

	elems := drainDecodedElements(t, dec)
	for _, elem := range elems {
		if elem.ElemType == ocsd.GenElemInstrRange {
			if elem.ISA != ocsd.ISAThumb2 {
				t.Fatalf("expected instruction range ISA %v, got %v", ocsd.ISAThumb2, elem.ISA)
			}
			return
		}
	}
	t.Fatal("expected an instruction range element")
}
