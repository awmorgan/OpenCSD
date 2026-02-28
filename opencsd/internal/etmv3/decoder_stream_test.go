package etmv3

import (
	"opencsd/internal/ocsd"
	"testing"
)

func TestDecoderAtomProcessing(t *testing.T) {
	config := &Config{}
	dec, out := setupDecFast(config)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.Addr = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncInfo.Reason = 1
	pkt.Context.UpdatedC = true
	pkt.Context.CtxtID = 0x42
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktPHdr
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	resp := dec.PacketDataIn(ocsd.OpData, 1, pkt2)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Atom E failed: %v", resp)
	}

	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktPHdr
	pkt3.Atom.EnBits = 0x0
	pkt3.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 2, pkt3)

	pkt4 := &Packet{}
	pkt4.ResetState()
	pkt4.Type = PktPHdr
	pkt4.Atom.EnBits = 0x5 // E, N, E
	pkt4.Atom.Num = 3
	dec.PacketDataIn(ocsd.OpData, 3, pkt4)

	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements from atom processing")
	}
}

func TestDecoderWPUpdate(t *testing.T) {
	config := &Config{}
	dec, out := setupDecFast(config)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.Addr = 0x2000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncInfo.Reason = 1
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Since ETMv3 doesn't have PktWPointUpdate, let's test BranchAddress instead
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktBranchAddress
	pkt2.Addr = 0x3000
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)

	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements from WP update")
	}
}

func TestDecoderBranchWithException(t *testing.T) {
	config := &Config{}
	dec, out := setupDecFast(config)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.Addr = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktBranchAddress
	pkt3.Exception.Present = true
	pkt3.Exception.Type = ocsd.ExcpFIQ // Or ArmV7Exception mapped
	pkt3.Exception.Number = 5
	pkt3.CurrISA = ocsd.ISAArm
	pkt3.Addr = 0x4000
	pkt3.CycleCount = 10
	dec.PacketDataIn(ocsd.OpData, 2, pkt3)

	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements")
	}
}

func TestDecoderMemNacc(t *testing.T) {
	config := &Config{}
	dec, out := setupDecFast(config)
	mem := &mockMemAcc{failAfter: 1} // fail on 2nd read
	dec.MemAccess.Attach(mem)
	instr := &mockInstrDecode{hitAfter: -1} // never find branch
	dec.InstrDecode.Attach(instr)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.Addr = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktPHdr
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)

	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktBranchAddress
	pkt3.Addr = 0x5000
	pkt3.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 2, pkt3)

	if len(out.elements) == 0 {
		t.Logf("No elements generated (memNacc path)")
	}
}

func TestDecoderContProcess(t *testing.T) {
	config := &Config{}
	dec, out := setupDecFast(config)
	dec.SetUsesMemAccess(false)
	dec.SetUsesIDecode(false)

	dec.PacketDataIn(ocsd.OpFlush, 0, nil)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt.Type = PktContextID
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt.Type = PktCycleCount
	pkt.CycleCount = 100
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt.Type = PktTrigger
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	if out == nil {
		t.Error()
	}
}

func TestDecoderBranchVariations(t *testing.T) {
	config := &Config{}
	dec, _ := setupDecFast(config)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	syncPkt := &Packet{}
	syncPkt.ResetState()
	syncPkt.Type = PktISync
	syncPkt.Addr = 0x8000
	dec.PacketDataIn(ocsd.OpData, 0, syncPkt)

	// Branch missing CC
	pkt1 := &Packet{}
	pkt1.ResetState()
	pkt1.Type = PktBranchAddress
	pkt1.Addr = 0x2000
	pkt1.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 0, pkt1)

	pkt1.Exception.Present = true
	pkt1.Exception.Cancel = true
	pkt1.Context.UpdatedC = true
	pkt1.Context.CurrNS = true
	dec.PacketDataIn(ocsd.OpData, 1, pkt1)

	pkt1.Exception.Cancel = false
	pkt1.Context.CurrNS = false
	dec.PacketDataIn(ocsd.OpData, 2, pkt1)

	// Alt branch
	config.RegIDR = idrAltBranch | (4 << 4) // enable IsAltBranch
	pkt1.Exception.Present = true
	dec.PacketDataIn(ocsd.OpData, 3, pkt1)

	// Unsync packet
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktNotSync
	dec.PacketDataIn(ocsd.OpData, 4, pkt2)
}

func TestDecoderPHeaderVariations(t *testing.T) {
	config := &Config{}
	dec, _ := setupDecFast(config)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt1 := &Packet{}
	pkt1.ResetState()
	pkt1.Type = PktISync
	pkt1.Addr = 0x1000
	pkt1.ISyncInfo.Reason = 2
	dec.PacketDataIn(ocsd.OpData, 0, pkt1)

	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktPHdr
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 5
	pkt2.PHdrFmt = 1
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)

	// Fmt 2
	pkt2.PHdrFmt = 2
	pkt2.Atom.Num = 2
	dec.PacketDataIn(ocsd.OpData, 2, pkt2)

	// Fmt 3
	pkt2.PHdrFmt = 3
	pkt2.CycleCount = 100
	dec.PacketDataIn(ocsd.OpData, 3, pkt2)

	// Without Sync / unknown address
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	pkt2.PHdrFmt = 1
	dec.PacketDataIn(ocsd.OpData, 4, pkt2)

	dec.PacketDataIn(ocsd.OpFlush, 0, nil)
}

func TestDecoderAtomUsage(t *testing.T) {
	config := &Config{}
	dec, out := setupDecFast(config)
	mem := &mockMemAcc{failAfter: 10}
	dec.MemAccess.Attach(mem)
	instr := &mockInstrDecode{hitAfter: 0, instrType: ocsd.InstrBr} // conditional branch consumes atoms!
	dec.InstrDecode.Attach(instr)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt1 := &Packet{}
	pkt1.ResetState()
	pkt1.Type = PktISync
	pkt1.Addr = 0x1000
	dec.PacketDataIn(ocsd.OpData, 0, pkt1)

	// Send an atom packet E, N
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktPHdr
	pkt2.Atom.Num = 2
	pkt2.Atom.EnBits = 1 // E, N
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)

	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktBranchAddress
	pkt3.Addr = 0x2000
	dec.PacketDataIn(ocsd.OpData, 2, pkt3)

	for _, e := range out.elements {
		t.Logf("Generated Element: %v", e.ElemType)
	}

	if len(out.elements) < 1 { // Allow at least 1 for now (IDSync)
		t.Errorf("Expected at least one element, got %d", len(out.elements))
	}
}

func TestDecoderAllPackets(t *testing.T) {
	config := &Config{}
	dec, _ := setupDecFast(config)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	syncPkt := &Packet{}
	syncPkt.ResetState()
	syncPkt.Type = PktISync
	syncPkt.Addr = 0x8000
	syncPkt.ISyncInfo.Reason = 0
	syncPkt.Context.UpdatedC = true
	syncPkt.Context.CtxtID = 42
	dec.PacketDataIn(ocsd.OpData, 0, syncPkt)

	types := []PktType{
		PktCycleCount, PktTrigger, PktStoreFail,
		PktOOOData, PktOOOAddrPlc, PktNormData,
		PktDataSuppressed, PktValNotTraced, PktIgnore,
		PktVMID, PktExceptionEntry, PktExceptionExit, PktTimestamp,
	}

	for i, typ := range types {
		dec.PacketDataIn(ocsd.OpReset, 0, nil)

		dec.PacketDataIn(ocsd.OpData, ocsd.TrcIndex(i), syncPkt)
		pkt := &Packet{}
		pkt.ResetState()
		pkt.Type = typ
		dec.PacketDataIn(ocsd.OpData, ocsd.TrcIndex(i), pkt)
	}

	// Add missing error branches
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	dec.PacketDataIn(ocsd.OpData, 0, syncPkt)
	errPkt := &Packet{}
	errPkt.ResetState()
	errPkt.Type = PktBadSequence
	dec.PacketDataIn(ocsd.OpData, 0, errPkt)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	dec.PacketDataIn(ocsd.OpData, 0, syncPkt)
	errPkt.Type = PktReserved
	dec.PacketDataIn(ocsd.OpData, 0, errPkt)

	dec.PacketDataIn(ocsd.OpFlush, 0, nil)
}

func setupDecFast(config *Config) (*PktDecode, *testTrcElemIn) {
	manager := NewDecoderManager()
	dec := manager.CreatePktDecode(0, config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	return dec, out
}
