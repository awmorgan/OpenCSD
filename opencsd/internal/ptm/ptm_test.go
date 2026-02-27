package ptm

import (
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type testTrcElemIn struct {
	elements []common.TraceElement
}

func (t *testTrcElemIn) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *common.TraceElement) ocsd.DatapathResp {
	t.elements = append(t.elements, *elem)
	return ocsd.RespCont
}

func TestPtmConfig(t *testing.T) {
	config := NewConfig()
	if config.MinorRev() != 1 { // 0x4100F310 >> 4 & 0xF
		t.Errorf("MinorRev was %d, expected 1", config.MinorRev())
	}

	config.RegCtrl = ctrlBranchBcast | ctrlCycleAcc | ctrlTSEna | ctrlRetStackEna | ctrlVMIDEna | (2 << 14) // CtxtIDbytes = 4
	if !config.EnaBranchBCast() || !config.EnaCycleAcc() || !config.EnaTS() || !config.EnaRetStack() || !config.EnaVMID() {
		t.Errorf("Expected all control enablers to be true")
	}
	if config.CtxtIDBytes() != 2 {
		t.Errorf("Expected CtxtIDBytes to be 2, was %d", config.CtxtIDBytes())
	}

	config.RegCCER = ccerTSImpl | ccerRestackImpl | ccerDmsbWpt | ccerTSDmsb | ccerVirtExt | ccerTSEncNat | ccerTS64Bit
	if !config.HasTS() || !config.HasRetStack() || !config.DmsbWayPt() || !config.DmsbGenTS() || !config.HasVirtExt() || !config.TSBinEnc() || !config.TSPkt64() {
		t.Errorf("Expected all CCER enablers to be true")
	}

	config.RegTrcID = 0xAA
	if config.TraceID() != 0x2A {
		t.Errorf("Expected TraceID 0x2A, got 0x%x", config.TraceID())
	}
}

func TestPtmErrorCases(t *testing.T) {
	config := NewConfig()
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config)
	dec := manager.CreatePktDecode(0, config)

	proc.PktOutI.Attach(dec)
	dec.SetUsesMemAccess(false)
	dec.SetUsesIDecode(false)
	outReceiver := &testTrcElemIn{}
	dec.TraceElemOut.Attach(outReceiver)

	// Incomplete packets, reserved instructions, etc.
	badBlocks := [][]uint8{
		{0xFF, 0x00, 0x01}, // Bad ASYNC
		{0x6E, 0x12},       // Short CtxtID
		{0x3C},             // Short VMID
		{0x42, 0x11, 0x22}, // Short TS
		{0x0A},             // Reserved
	}

	for _, b := range badBlocks {
		proc.TraceDataIn(ocsd.OpData, 0, b)
		proc.TraceDataIn(ocsd.OpReset, 0, nil)
	}
}

func TestPtmComprehensive(t *testing.T) {
	config := NewConfig()
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config)
	dec := manager.CreatePktDecode(0, config)

	proc.PktOutI.Attach(dec)
	dec.SetUsesMemAccess(false)
	dec.SetUsesIDecode(false)
	outReceiver := &testTrcElemIn{}
	dec.TraceElemOut.Attach(outReceiver)

	dataBlock := []uint8{
		// ASYNC Sequence
		0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,

		// ISYNC
		0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,

		// Trigger
		0x0C,

		// ContextID
		0x6E, 0x12, 0x34, 0x56, 0x78,

		// VMID
		0x3C, 0xAB,

		// Timestamp
		0x42, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,

		// Timestamp 2
		0x46, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,

		// Exception Return
		0x76,

		// Ignore
		0x66,

		// WPointUpdate
		0x72, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,

		// BranchAddress (format is odd header byte, 1 in bit 0)
		0x01, 0x12, 0x34, 0x56, 0x78,

		// Atom
		0x80, 0x90, 0xA0, 0xC0,

		// Reserved
		0x0A,
	}

	processed, resp := proc.TraceDataIn(ocsd.OpData, 0, dataBlock)
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(dataBlock)), nil)

	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("processData returned fatal error: %v, processed=%d", resp, processed)
	}

	if len(outReceiver.elements) == 0 {
		t.Errorf("Expected elements to be generated")
	}
}

func TestPtmPacketString(t *testing.T) {
	pkt := &Packet{}
	pkt.ResetState()

	if pkt.String() != "NOTSYNC : PTM Not Synchronised; " {
		t.Errorf("Unexpected string for initial state: %s", pkt.String())
	}

	pkt.Type = PktBranchAddress
	pkt.CurrISA = ocsd.ISAArm
	pkt.PrevISA = ocsd.ISAThumb2
	pkt.AddrVal = 0x1000
	pkt.Context.Updated = true
	pkt.Context.CurrNS = true
	pkt.Context.CurrHyp = true
	pkt.Exception.Present = true
	pkt.Exception.Number = 3
	pkt.CCValid = true
	pkt.CycleCount = 10
	str := pkt.String()
	if str != "BRANCH_ADDRESS : Branch address packet; Addr=0x1000; ISA=ARM(32); NS; Hyp; Excep=Hyp [03]; Cycles=10; " {
		t.Errorf("Unexpected formatting for Branch: %s", str)
	}

	pkt.CurrISA = ocsd.ISAAArch64
	if pkt.getISAStr() != "ISA=AArch64; " {
		t.Errorf("ISA mismatch")
	}
	pkt.CurrISA = ocsd.ISATee
	if pkt.getISAStr() != "ISA=ThumbEE; " {
		t.Errorf("ISA mismatch")
	}
	pkt.CurrISA = ocsd.ISAJazelle
	if pkt.getISAStr() != "ISA=Jazelle; " {
		t.Errorf("ISA mismatch")
	}
	pkt.CurrISA = ocsd.ISAUnknown
	if pkt.getISAStr() != "ISA=Unknown; " {
		t.Errorf("ISA mismatch")
	}

	pkt.Type = PktAtom
	pkt.Atom.EnBits = 0x5 // 101 -> E, N, E
	pkt.Atom.Num = 3
	pkt.CCValid = false
	if pkt.String() != "ATOM : Atom packet; ENE; " {
		t.Errorf("Unexpected formatting for Atom: %s", pkt.String())
	}

	pkt.Type = PktBadSequence
	pkt.ErrType = PktVMID
	if pkt.String() != "BAD_SEQUENCE : Invalid sequence in packet; [VMID]; " {
		t.Errorf("Unexpected formatting for Bad Sequence: %s", pkt.String())
	}

	pkt.Type = PktContextID
	pkt.Context.CtxtID = 0xAA
	if pkt.String() != "CTXTID : Context ID packet; CtxtID=0x000000aa; " {
		t.Errorf("Unexpected formatting for ContextID: %s", pkt.String())
	}

	pkt.Type = PktVMID
	pkt.Context.VMID = 0x55
	if pkt.String() != "VMID : VM ID packet; VMID=0x55; " {
		t.Errorf("Unexpected formatting for VMID: %s", pkt.String())
	}

	pkt.Type = PktTrigger
	if pkt.String() != "TRIGGER : Trigger Event packet; " {
		t.Errorf("Unexpected formatting for Trigger: %s", pkt.String())
	}

	pkt.Type = PktExceptionRet
	if pkt.String() != "ERET : Exception return packet; " {
		t.Errorf("Unexpected formatting for ERET: %s", pkt.String())
	}

	pkt.Type = PktIgnore
	if pkt.String() != "IGNORE : Ignore packet; " {
		t.Errorf("Unexpected formatting for Ignore: %s", pkt.String())
	}

	pkt.Type = PktTimestamp
	pkt.Timestamp = 0x99
	pkt.CCValid = true
	pkt.CycleCount = 20
	if pkt.String() != "TIMESTAMP : Timestamp packet; TS=0x99(153); Cycles=20; " {
		t.Errorf("Unexpected formatting for Timestamp: %s", pkt.String())
	}

	pkt.Type = PktISync
	pkt.ISyncReason = ocsd.ISyncPeriodic
	pkt.AddrVal = 0x2000
	pkt.Context.CurrNS = true
	pkt.Context.CurrHyp = true
	pkt.Context.UpdatedC = true
	pkt.Context.CtxtID = 0xBB
	pkt.CCValid = true
	pkt.CycleCount = 30
	pkt.CurrISA = ocsd.ISAThumb2
	if pkt.String() != "ISYNC : Instruction Synchronisation packet; (Periodic); Addr=0x00002000; NS; Hyp; CtxtID=000000bb; ISA=Thumb2; Cycles=30; " {
		t.Errorf("Unexpected formatting for ISync: %s", pkt.String())
	}
}

func TestPtmDecoder(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)
	dec.SetUsesMemAccess(false)
	dec.SetUsesIDecode(false)

	outReceiver := &testTrcElemIn{}
	dec.TraceElemOut.Attach(outReceiver)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// Send Async
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Send ISYNC
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	dec.PacketDataIn(ocsd.OpData, 1, pkt)

	// Send Exception
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Exception.Present = true
	pkt.Exception.Number = 3
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	// Send Timestamp
	pkt.ResetState()
	pkt.Type = PktTimestamp
	pkt.Timestamp = 0x123
	dec.PacketDataIn(ocsd.OpData, 3, pkt)

	// Send Event
	pkt.ResetState()
	pkt.Type = PktTrigger
	dec.PacketDataIn(ocsd.OpData, 4, pkt)

	// Send ContextID
	pkt.ResetState()
	pkt.Type = PktContextID
	pkt.Context.CtxtID = 0x42
	dec.PacketDataIn(ocsd.OpData, 5, pkt)

	// Send VMID
	pkt.ResetState()
	pkt.Type = PktVMID
	pkt.Context.VMID = 0x43
	dec.PacketDataIn(ocsd.OpData, 6, pkt)

	dec.PacketDataIn(ocsd.OpFlush, 7, nil)
	dec.PacketDataIn(ocsd.OpEOT, 8, nil)
}

type mockMemAcc struct{}

func (m *mockMemAcc) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	return reqBytes, []byte{0, 0, 0, 0}, ocsd.OK
}
func (m *mockMemAcc) InvalidateMemAccCache(csTraceID uint8) {}

type mockInstrDecode struct{}

func (m *mockInstrDecode) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	instrInfo.InstrSize = 4
	instrInfo.Type = ocsd.InstrBr
	instrInfo.SubType = ocsd.SInstrNone
	instrInfo.BranchAddr = instrInfo.InstrAddr + 4
	return ocsd.OK
}

func TestPtmDecoderFull(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	memAcc := &mockMemAcc{}
	dec.MemAccess.Attach(memAcc)
	instrDec := &mockInstrDecode{}
	dec.InstrDecode.Attach(instrDec)

	outReceiver := &testTrcElemIn{}
	dec.TraceElemOut.Attach(outReceiver)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// Send ISYNC
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	pkt.Context.UpdatedC = true
	pkt.CurrISA = ocsd.ISAArm
	r1 := dec.PacketDataIn(ocsd.OpData, 1, pkt)
	if r1 != ocsd.RespCont {
		t.Errorf("ISYNC failed! resp=%v", r1)
	}

	// Send Atom
	pkt.ResetState()
	pkt.Type = PktAtom
	pkt.Atom.EnBits = 0x1
	pkt.Atom.Num = 1
	resp := dec.PacketDataIn(ocsd.OpData, 2, pkt)
	if resp != ocsd.RespCont {
		t.Errorf("Atom failed! resp=%v", resp)
	}

	// Send Branch Addr
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.AddrVal = 0x2000
	dec.PacketDataIn(ocsd.OpData, 3, pkt)

	// Send Waypoint update
	pkt.ResetState()
	pkt.Type = PktWPointUpdate
	pkt.AddrVal = 0x3000
	dec.PacketDataIn(ocsd.OpData, 4, pkt)

	if len(outReceiver.elements) == 0 {
		t.Errorf("Expected elements")
	}
}
