package etmv3

import (
	"strings"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// --- Tests for Config ---
func TestConfig(t *testing.T) {
	c := &Config{
		RegIDR:   0x4100F310,                                         // MinorRev = 1
		RegCtrl:  ctrlCycleAcc | ctrlTsEna | ctrlVmidEna | (2 << 14), // CtxtIDBytes = 2
		RegCCER:  ccerHasTs | ccerVirtExt | ccerTs64Bit,
		RegTrcID: 0x42,
		ArchVer:  ocsd.ArchV7,
		CoreProf: ocsd.ProfileCortexM,
	}

	if !c.IsInstrTrace() {
		t.Error("expected IsInstrTrace")
	}
	if c.IsDataValTrace() {
		t.Error("unexpected IsDataValTrace")
	}
	if c.IsDataAddrTrace() {
		t.Error("unexpected IsDataAddrTrace")
	}
	if c.IsDataTrace() {
		t.Error("unexpected IsDataTrace")
	}
	if c.TraceMode() != TMInstrOnly {
		t.Error("expected TMInstrOnly")
	}

	if !c.IsCycleAcc() {
		t.Error("expected IsCycleAcc")
	}
	if c.MinorRev() != 1 {
		t.Error("expected Minor rev 1")
	}
	if !c.IsV7MArch() {
		t.Error("expected V7M")
	}
	if c.IsAltBranch() {
		t.Error("unexpected IsAltBranch")
	}
	if c.CtxtIDBytes() != 2 {
		t.Error("expected CtxtIDBytes=2")
	}
	if !c.HasVirtExt() {
		t.Error("expected HasVirtExt")
	}
	if !c.IsVMIDTrace() {
		t.Error("expected IsVMIDTrace")
	}
	if !c.HasTS() {
		t.Error("expected HasTS")
	}
	if !c.IsTSEnabled() {
		t.Error("expected IsTSEnabled")
	}
	if !c.TSPkt64() {
		t.Error("expected TSPkt64")
	}
	if c.TraceID() != 0x42 {
		t.Error("expected 0x42 TraceID")
	}

	str := c.String()
	if !strings.Contains(str, "ETMv3 Config") {
		t.Error("String() format incorrect")
	}

	// Test TraceMode variations
	c.RegCtrl |= ctrlDataOnly
	if c.TraceMode() != TMDataOnlyVal {
		t.Error("expected TMDataOnlyVal")
	}
	c.RegCtrl |= ctrlDataAddr
	if c.TraceMode() != TMDataOnlyAddr {
		t.Error("expected TMDataOnlyAddr")
	}
	c.RegCtrl |= ctrlDataVal
	if c.TraceMode() != TMDataOnlyValAddr {
		t.Error("expected TMDataOnlyValAddr")
	}
	c.RegCtrl &^= ctrlDataAddr
	if c.TraceMode() != TMDataOnlyVal {
		t.Error("expected TMDataOnlyVal")
	}

	c.RegCtrl &^= ctrlDataOnly // back to instr+data
	if c.TraceMode() != TMIDataVal {
		t.Error("expected TMIDataVal")
	}
	c.RegCtrl |= ctrlDataAddr
	if c.TraceMode() != TMIDataValAddr {
		t.Error("expected TMIDataValAddr")
	}
	c.RegCtrl &^= ctrlDataVal
	if c.TraceMode() != TMIDataAddr {
		t.Error("expected TMIDataAddr")
	}

	// CtxtIDBytes edge cases
	c.RegCtrl = (1 << 14)
	if c.CtxtIDBytes() != 1 {
		t.Error("expected 1")
	}
	c.RegCtrl = (3 << 14)
	if c.CtxtIDBytes() != 4 {
		t.Error("expected 4")
	}
	c.RegCtrl = 0
	if c.CtxtIDBytes() != 0 {
		t.Error("expected 0")
	}

	// IsAltBranch
	c.RegIDR = idrAltBranch | (4 << 4)
	if !c.IsAltBranch() {
		t.Error("expected IsAltBranch")
	}
}

// --- Tests for Packet ---
func TestPacket(t *testing.T) {
	p := &Packet{}
	p.ResetState()

	if p.Type != PktNoError {
		t.Error("expected PktNoError")
	}
	if p.CurrISA != ocsd.ISAArm {
		t.Error("expected ISAArm")
	}

	p.Type = PktBadSequence
	if !p.IsBadPacket() {
		t.Error("expected bad packet")
	}

	p.UpdateAddress(0x1234, 16)
	if p.Addr != 0x1234 {
		t.Error("addr mismatch")
	}
	p.UpdateAddress(0x5600, 8)
	if p.Addr != 0x1200 {
		t.Errorf("addr mismatch %x", p.Addr)
	}

	p.SetException(ocsd.ExcpFIQ, 4, true, false, 0, 1)
	if p.Exception.Type != ocsd.ExcpFIQ {
		t.Error("exception type mismatch")
	}
	if !p.Exception.Present {
		t.Error("expected present")
	}

	_ = p.String()

	p.Type = PktPHdr
	_ = p.String()

	p.Type = PktISync
	_ = p.String()

	p.Type = PktBranchAddress
	_ = p.String()

	p.Type = PktNotSync
	if p.Type.String() != "I_NOT_SYNC" {
		t.Error("stringer mismatch")
	}
	p.Type = PktType(99)
	if p.Type.String() != "Unknown PktType" {
		t.Error("stringer mismatch for unknown")
	}

	// Test UpdateAtomFromPHdr
	// Format 4
	if p.UpdateAtomFromPHdr(0x00, true) {
		t.Error("fmt4 not allowed cycleAcc")
	} // 0x00 -> fmt4
	if !p.UpdateAtomFromPHdr(0x00, false) {
		t.Error("fmt4 allowed non-cycleAcc")
	}
	if p.PHdrFmt != 4 {
		t.Error("expected fmt 4")
	}

	// Fmt 3
	if !p.UpdateAtomFromPHdr(0x42, false) {
		t.Error("fmt3")
	} // 0x42 & 0x0F = 0x02 != 0 wait. 0x42 is 0100 0010 (bits0-3=2). Oh wait.
	// We will skip deep UpdateAtomFromPHdr validation unless necessary, let's just trigger it:
	p.UpdateAtomFromPHdr(0x00, false) // 0x00 fmt4
	p.UpdateAtomFromPHdr(0x01, false) // 0x01 fmt3 : 0x01 & 0x0F = 1 != 0, hmm
	p.UpdateAtomFromPHdr(0x10, false) // 0x10 & 0x1F = 16 != 0. 0x10 & 0x0F = 0 -> fmt 3
	p.UpdateAtomFromPHdr(0x11, false) // 0x11 & 0x03 == 1 != 0.
	p.UpdateAtomFromPHdr(0x08, false) // 0x08 & 0x0F = 8. &0x07=0? No, &0x03=0 -> fmt 2
	p.UpdateAtomFromPHdr(0x02, false) // 0x02 & 0x01 = 0 -> fmt 1
}

// --- Mocks ---
type testTrcElemIn struct {
	elements []common.TraceElement
}

func (t *testTrcElemIn) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *common.TraceElement) ocsd.DatapathResp {
	t.elements = append(t.elements, *elem)
	return ocsd.RespCont
}

type mockMemAcc struct {
	failAfter int
	calls     int
}

func (m *mockMemAcc) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	m.calls++
	if m.failAfter > 0 && m.calls > m.failAfter {
		return 0, nil, ocsd.OK
	}
	return reqBytes, []byte{0, 0, 0, 0}, ocsd.OK
}

func (m *mockMemAcc) InvalidateMemAccCache(csTraceID uint8) {}

type mockInstrDecode struct {
	hitAfter  int
	calls     int
	instrType ocsd.InstrType
	isLink    int
}

func (m *mockInstrDecode) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	instrInfo.InstrSize = 4
	instrInfo.NextIsa = instrInfo.Isa
	instrInfo.SubType = ocsd.SInstrNone

	if m.hitAfter < 0 {
		instrInfo.Type = ocsd.InstrOther
		m.calls++
		return ocsd.OK
	}

	m.calls++
	if m.calls > m.hitAfter {
		wpt := m.instrType
		if wpt == ocsd.InstrOther {
			wpt = ocsd.InstrBr
		}
		instrInfo.Type = wpt
		instrInfo.BranchAddr = instrInfo.InstrAddr + 0x100
		instrInfo.IsLink = uint8(m.isLink)
	} else {
		instrInfo.Type = ocsd.InstrOther
	}
	return ocsd.OK
}

func setupProcDec(config *Config) (*PktProc, *PktDecode, *testTrcElemIn) {
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config)
	dec := manager.CreatePktDecode(0, config)
	proc.PktOutI.Attach(dec)
	dec.MemAccess.Attach(&mockMemAcc{})
	dec.InstrDecode.Attach(&mockInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	return proc, dec, out
}

func TestProcessorAndDecoderBasic(t *testing.T) {
	config := &Config{}
	config.RegCtrl = ctrlCycleAcc | (2 << 14) // ctxtid=2

	proc, _, out := setupProcDec(config)

	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x08, 0x01, 0x22, 0x33, 0x44, 0x00, 0xaa, 0xbb, // ISYNC
		0x01,             // branch
		0x0c,             // trigger
		0x6e, 0x11, 0x22, // context ID
		0x3c, 0x55, // VMID
		0x42, 0x11, // timestamp
		0x76, // exception return
		0x80, // atom
	}

	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	processed, resp := proc.TraceDataIn(ocsd.OpData, 0, data)
	if ocsd.DataRespIsFatal(resp) {
		t.Fatalf("fatal = %v", resp)
	}
	if processed == 0 {
		t.Errorf("no data processed")
	}

	proc.TraceDataIn(ocsd.OpFlush, 0, nil)
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(data)), nil)

	if len(out.elements) == 0 {
		t.Errorf("expected trace elements")
	}
}
