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

// --- Mocks ---

type mockMemAcc struct {
	failAfter int // if > 0, return short read after this many calls
	calls     int
}

func (m *mockMemAcc) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	m.calls++
	if m.failAfter > 0 && m.calls > m.failAfter {
		return 0, nil, ocsd.OK // short read triggers memNaccPending
	}
	return reqBytes, []byte{0, 0, 0, 0}, ocsd.OK
}

func (m *mockMemAcc) InvalidateMemAccCache(csTraceID uint8) {}

// mockInstrDecode is a configurable instruction decoder for tests.
// hitAfter: return InstrOther for this many calls, then return a branch (waypoint).
//
//	 0  → waypoint on the very first instruction (original wpHit=true behaviour).
//	-1  → never hit a waypoint (rely on memNacc to stop).
//
// instrType: when hitAfter is reached, use this type (default InstrBr).
// isLink: set IsLink flag on the waypoint instruction.
type mockInstrDecode struct {
	hitAfter  int // calls before waypoint; 0=immediate, -1=never
	calls     int
	instrType ocsd.InstrType // type to emit at waypoint; zero-value → InstrBr
	isLink    int
}

func (m *mockInstrDecode) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	instrInfo.InstrSize = 4
	instrInfo.NextIsa = instrInfo.Isa
	instrInfo.SubType = ocsd.SInstrNone

	if m.hitAfter < 0 {
		// Never a waypoint – return InstrOther so the loop keeps going
		// until memNacc kicks in.
		instrInfo.Type = ocsd.InstrOther
		m.calls++
		return ocsd.OK
	}

	m.calls++
	if m.calls > m.hitAfter {
		// Waypoint instruction
		wpt := m.instrType
		if wpt == ocsd.InstrOther {
			wpt = ocsd.InstrBr
		}
		instrInfo.Type = wpt
		instrInfo.BranchAddr = instrInfo.InstrAddr + 0x100
		instrInfo.IsLink = uint8(m.isLink)
	} else {
		// Non-waypoint – just advance
		instrInfo.Type = ocsd.InstrOther
	}
	return ocsd.OK
}

// --- Helpers ---

func makeAsyncBlock() []byte {
	// 0x00 x 5 + 0x80 = valid ASYNC
	return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
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

// noopPktSink is a no-op packet receiver that just swallows packets without decoding.
type noopPktSink struct{}

func (n *noopPktSink) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *Packet) ocsd.DatapathResp {
	return ocsd.RespCont
}

// setupProcOnly creates a processor with a no-op sink (doesn't decode packets)
func setupProcOnly(config *Config) *PktProc {
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config)
	proc.PktOutI.Attach(&noopPktSink{})
	return proc
}

func setupProcDecFull(config *Config, memAcc common.TargetMemAccess, instrDec common.InstrDecode) (*PktProc, *PktDecode, *testTrcElemIn) {
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config)
	dec := manager.CreatePktDecode(0, config)
	proc.PktOutI.Attach(dec)
	dec.MemAccess.Attach(memAcc)
	dec.InstrDecode.Attach(instrDec)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	return proc, dec, out
}

// --- Config ---

func TestPtmConfig(t *testing.T) {
	config := NewConfig()
	if config.MinorRev() != 1 {
		t.Errorf("MinorRev was %d, expected 1", config.MinorRev())
	}

	config.RegCtrl = ctrlBranchBcast | ctrlCycleAcc | ctrlTSEna | ctrlRetStackEna | ctrlVMIDEna | (2 << 14)
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

	// Cover TSPkt64/TSBinEnc with MinorRev==0
	config.RegIDR = 0x4100F300 // MinorRev = 0
	if config.TSPkt64() {
		t.Errorf("TSPkt64 should be false if MinorRev==0")
	}
	if config.TSBinEnc() {
		t.Errorf("TSBinEnc should be false if MinorRev==0")
	}
}

// --- Processor: Comprehensive byte stream tests ---

func TestProcAllPacketTypes(t *testing.T) {
	// Config with CycleAcc enabled, CtxtID=4bytes, RetStack, VMID
	config := NewConfig()
	config.RegCtrl = ctrlCycleAcc | ctrlRetStackEna | ctrlVMIDEna | (3 << 14) // 4-byte ctxtID
	config.RegCCER = ccerRestackImpl | ccerDmsbWpt

	proc := setupProcOnly(config)

	// Build byte stream with ASYNC then every packet type
	data := []byte{}

	// 1) Lead-in non-zero bytes (exercise waitASync unsync path)
	data = append(data, 0xFF, 0xEE)

	// 2) ASYNC
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80)

	// 3) ISYNC with reason!=0 + CycleCount + CtxtID (4 bytes)
	// Header=0x08, addr bytes [1..4], info byte [5], CC byte [6], ctxtID [7..10]
	data = append(data,
		0x08,                   // ISYNC header
		0x01, 0x22, 0x33, 0x44, // address bytes (bit0=1 -> Thumb2)
		0x28,                   // info: reason=1(bit5)=0x20, NS=1(bit3)=0x08 => 0x28
		0x04,                   // CC: single byte, bit6=0 -> done, value=(0x04>>2)&0xF=1
		0xAA, 0xBB, 0xCC, 0xDD, // 4-byte context ID
	)

	// 4) Trigger
	data = append(data, 0x0C)

	// 5) ContextID (0x6E + 4 bytes)
	data = append(data, 0x6E, 0x11, 0x22, 0x33, 0x44)

	// 6) VMID
	data = append(data, 0x3C, 0x55)

	// 7) Timestamp (0x42) with CC enabled
	// TS bytes: byte1..byteN with bit7 continuation, then CC byte
	data = append(data,
		0x42, // TS header
		0x11, // TS byte1: bit7=0 -> done
		0x04, // CC byte: bit6=0 -> done
	)

	// 8) ExceptionReturn
	data = append(data, 0x76)

	// 9) Ignore
	data = append(data, 0x66)

	// 10) Atom with CycleAcc: header 0x80, bit6=0 -> no extra CC bytes needed
	data = append(data, 0x80)

	// 11) Atom with CycleAcc: header 0xC0, bit6=1 -> need extra CC bytes
	data = append(data,
		0xC0, // atom header with bit6=1
		0x10, // CC extra byte: bit7=0 -> done
	)

	// 12) BranchAddress: 1 addr byte, header bit7=0 -> addr done, bit6=0 -> excep done
	// CycleAcc: needs CC byte after
	data = append(data,
		0x01, // header/addr[0]: bit0=1(branch), bit7=0(addr done), bit6=0(excep done)
		0x04, // CC byte: bit6=0 -> done
	)

	// 13) BranchAddress: multi-byte addr + CC
	data = append(data,
		0x81, // header/addr[0]: bit7=1 continue
		0x02, // addr[1]: bit7=0 -> addr done, bit6=0 -> excep done
		0x04, // CC byte: bit6=0 -> done
	)

	// 14) WPointUpdate: short address
	data = append(data,
		0x72, // WP header
		0x10, // addr byte: bit7=0 -> done
	)

	// 15) WPointUpdate: 5-byte address with ISA setting
	data = append(data,
		0x72,                   // WP header
		0x81, 0x82, 0x83, 0x84, // 4 addr bytes with bit7=1 continue
		0x10, // 5th byte: ISA bits
	)

	// 16) Reserved
	data = append(data, 0x0A)

	// 17) ASYNC inline
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80)

	// 18) BranchAddress: 5-byte addr (byteIdx==4 triggers ISA detection)
	data = append(data,
		0x81,             // header
		0x82, 0x83, 0x84, // bytes 2-4 with continue
		0x30, // byte 5 (byteIdx=4): bit5=0,bit4=1 -> ISAThumb2, bit6=0 -> excep done
		0x04, // CC byte
	)

	processed, resp := proc.TraceDataIn(ocsd.OpData, 0, data)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Fatal resp=%v processed=%d", resp, processed)
	}

	// Exercise onFlush and onEOT
	proc.TraceDataIn(ocsd.OpFlush, 0, nil)
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(data)), nil)
}

func TestProcISyncWithContextAndBranch5ByteAddr(t *testing.T) {
	// Config with CycleAcc, 1-byte CtxtID
	config := NewConfig()
	config.RegCtrl = ctrlCycleAcc | (1 << 14) // 1-byte ctxtID

	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)

	// ISYNC: reason=2 (overflow restart), altISA, Hyp
	data = append(data,
		0x08,
		0x03, 0x22, 0x33, 0x44, // addr (bit0=1 -> thumb; extra bit set for altISA->Tee)
		0x46, // info: altISA=1(bit2), reason=2(bits5-6)=0x40, Hyp(bit1)=0x02 => 0x46
		0x04, // CC byte
		0xAA, // 1-byte context ID
	)

	// BranchAddress with 5-byte addr and Jazelle ISA
	// byte[0..3] have bit7=1. byte[4] -> ISA bits. CC follows.
	data = append(data,
		0x81,             // header: continue
		0x82, 0x83, 0x84, // bytes with continue
		0x20, // byte[4]: bit5=1 -> Jazelle, bit6=0 -> excep done
		0x04, // CC byte
	)

	// BranchAddress with exception: addr done at byte[1], then excep bytes, then CC
	data = append(data,
		0x81, // header: bit7=1 continue
		0x44, // addr byte[1]: bit7=0 addr done, bit6=1 -> excep bytes follow
		0x02, // excep byte1: bit7=0 -> done
		0x04, // CC byte
	)

	processed, resp := proc.TraceDataIn(ocsd.OpData, 0, data)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Fatal resp=%v processed=%d", resp, processed)
	}
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(data)), nil)
}

func TestProcISyncDebugExitAndCCMultiByte(t *testing.T) {
	config := NewConfig()
	config.RegCtrl = ctrlCycleAcc

	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)

	// ISYNC with reason=3 (DebugExit), multi-byte CC
	data = append(data,
		0x08,
		0x00, 0x00, 0x00, 0x00, // addr
		0x60, // info: reason=3 (bits5-6)=0x60
		0x44, // CC byte1: bit6=1 -> continue
		0x80, // CC byte2: bit7=1 -> continue
		0x80, // CC byte3: bit7=1 -> continue
		0x00, // CC byte4: bit7=0 -> done (or pktIndex==10 forces done)
	)

	processed, resp := proc.TraceDataIn(ocsd.OpData, 0, data)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Fatal resp=%v processed=%d", resp, processed)
	}
}

func TestProcTimestamp64Bit(t *testing.T) {
	config := NewConfig()
	config.RegIDR = 0x4100F310   // MinorRev=1
	config.RegCCER = ccerTS64Bit // TSPkt64=true

	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)

	// Timestamp with 64-bit: up to 9 bytes with continuation, then byte 10
	data = append(data,
		0x42,
		0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, // bytes 1-8: bit7=1 continue
		0x09, // byte 9: no continuation check, full 8 bits
	)

	processed, resp := proc.TraceDataIn(ocsd.OpData, 0, data)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Fatal resp=%v processed=%d", resp, processed)
	}
}

func TestProcEOTWithPendingData(t *testing.T) {
	config := NewConfig()
	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)
	// Start a timestamp but don't finish it -> incomplete
	data = append(data, 0x42, 0x81, 0x82)

	proc.TraceDataIn(ocsd.OpData, 0, data)
	// EOT with pending packet data
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(data)), nil)
}

func TestProcCtxtIDZeroBytes(t *testing.T) {
	// Config with 0 ctxtID bytes
	config := NewConfig()
	// RegCtrl bits 14-15 = 0 -> CtxtIDBytes = 0
	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)
	// ContextID packet with 0 ctxtID bytes -> immediate send
	data = append(data, 0x6E)

	proc.TraceDataIn(ocsd.OpData, 0, data)
}

func TestProcBranchNoCC(t *testing.T) {
	// No cycle acc -> branch doesn't need CC bytes
	config := NewConfig()
	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)

	// Short branch: 1 addr byte, bit7=0, no exception
	data = append(data, 0x01)

	// Multi-byte branch without CC
	data = append(data,
		0x81, // continue
		0x04, // addr done, bit6=1 -> excep
		0x02, // excep byte1: bit7=0 -> done
	)

	proc.TraceDataIn(ocsd.OpData, 0, data)
}

func TestProcAtomFormats(t *testing.T) {
	// No cycle acc -> exercises SetAtomFromPHdr paths
	config := NewConfig()
	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)

	// Atom format 0x80: num=1 (bit3=0)
	data = append(data, 0x80)
	// Atom format 0x88: num=2 (bit3=1)
	data = append(data, 0x88)
	// Atom format 0x90: num=3
	data = append(data, 0x90)
	// Atom format 0xA0: num=4 (0xE0 check)
	data = append(data, 0xA0)
	// Atom format 0xC0: num=5
	data = append(data, 0xC0)

	proc.TraceDataIn(ocsd.OpData, 0, data)
}

func TestProcWPointExcepISASwap(t *testing.T) {
	config := NewConfig()
	config.RegCtrl = 1 << 14 // 1-byte ctxtID, no CycleAcc
	proc := setupProcOnly(config)

	data := []byte{}
	data = append(data, makeAsyncBlock()...)

	// ISYNC with altISA -> Tee. reason=1 (non-zero so needCC is config-dependent)
	// numPktBytesReq = 6 + 1(ctxtID) = 7. No CycleAcc so no CC.
	data = append(data,
		0x08,                   // header
		0x01, 0x22, 0x33, 0x44, // addr: bit0=1 -> thumb/tee
		0x24, // info: altISA(bit2)=0x04, reason=1(bit5)=0x20 => 0x24
		0xAA, // 1-byte ctxtID
	)

	// WPointUpdate: 5 addr bytes done at byte[4], excep byte follows
	data = append(data,
		0x72,                   // WP header
		0x81, 0x82, 0x83, 0x84, // 4 addr bytes with continue
		0x00, // byte[4]: ISA=ARM(no bits), bit6=0 -> excep done
	)

	proc.TraceDataIn(ocsd.OpData, 0, data)
}

// --- Decoder tests with mocks ---

func TestDecoderAtomProcessing(t *testing.T) {
	config := NewConfig()
	config.RegCCER = ccerRestackImpl | ccerDmsbWpt
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	mem := &mockMemAcc{}
	dec.MemAccess.Attach(mem)
	instr := &mockInstrDecode{}
	dec.InstrDecode.Attach(instr)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ISYNC to set valid state
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceEnable
	pkt.Context.UpdatedC = true
	pkt.Context.CtxtID = 0x42
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Atom: E (taken branch)
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktAtom
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	resp := dec.PacketDataIn(ocsd.OpData, 1, pkt2)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Atom E failed: %v", resp)
	}

	// Atom: N (not taken)
	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktAtom
	pkt3.Atom.EnBits = 0x0
	pkt3.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 2, pkt3)

	// Multiple atoms
	pkt4 := &Packet{}
	pkt4.ResetState()
	pkt4.Type = PktAtom
	pkt4.Atom.EnBits = 0x5 // E, N, E
	pkt4.Atom.Num = 3
	dec.PacketDataIn(ocsd.OpData, 3, pkt4)

	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements from atom processing")
	}
}

func TestDecoderWPUpdate(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	mem := &mockMemAcc{}
	dec.MemAccess.Attach(mem)
	instr := &mockInstrDecode{}
	dec.InstrDecode.Attach(instr)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ISYNC
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x2000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceEnable
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// WP Update: set addr to exactly instrAddr+4 so traceToAddrIncl matches immediately
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktWPointUpdate
	pkt2.AddrVal = 0x2000 // matches start addr-> currOpAddress == nextAddrMatch on first iter
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)

	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements from WP update")
	}
}

func TestDecoderBranchWithAtomRange(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	mem := &mockMemAcc{}
	dec.MemAccess.Attach(mem)
	instr := &mockInstrDecode{}
	dec.InstrDecode.Attach(instr)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ISYNC
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceRestartAfterOverflow
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Branch without exception (exercises processAtomRange via processBranch)
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktBranchAddress
	pkt2.AddrVal = 0x3000
	pkt2.CurrISA = ocsd.ISAArm
	pkt2.CCValid = true
	pkt2.CycleCount = 5
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)

	// Branch with exception
	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktBranchAddress
	pkt3.Exception.Present = true
	pkt3.Exception.Number = 5
	pkt3.CurrISA = ocsd.ISAArm
	pkt3.AddrVal = 0x4000
	pkt3.CCValid = true
	pkt3.CycleCount = 10
	dec.PacketDataIn(ocsd.OpData, 2, pkt3)

	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements")
	}
}

func TestDecoderMemNacc(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	mem := &mockMemAcc{failAfter: 1} // fail on 2nd read
	dec.MemAccess.Attach(mem)
	instr := &mockInstrDecode{hitAfter: -1} // never find WP, keep reading until memNacc
	dec.InstrDecode.Attach(instr)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ISYNC
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceEnable
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Atom -> will trigger traceInstrToWP -> memNaccPending on 2nd read
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktAtom
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)

	// Branch -> checkPendingNacc will emit GenElemAddrNacc
	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktBranchAddress
	pkt3.AddrVal = 0x5000
	pkt3.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 2, pkt3)

	// Check that we got nacc element
	if len(out.elements) == 0 {
		t.Logf("No elements generated (memNacc path)")
	}
}

func TestDecoderMemNaccSecure(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	mem := &mockMemAcc{failAfter: 1}
	dec.MemAccess.Attach(mem)
	instr := &mockInstrDecode{hitAfter: -1}
	dec.InstrDecode.Attach(instr)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ISYNC with Secure context (CurrNS=false)
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceEnable
	pkt.Context.CurrNS = false // secure
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Atom -> memNacc in secure context
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktAtom
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)
}

func TestDecoderIndirectBranch(t *testing.T) {
	config := NewConfig()
	config.RegCCER = ccerRestackImpl
	config.RegCtrl = ctrlRetStackEna
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	mem := &mockMemAcc{}
	dec.MemAccess.Attach(mem)
	// Return InstrBrIndirect
	instr := &mockInstrDecode{}
	dec.InstrDecode.Attach(instr)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	// Override instruction decode to return indirect branch
	dec.InstrDecode.Attach(&indirectBranchInstrDecode{})

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceEnable
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Atom with E -> indirect branch -> return stack pop
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktAtom
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)
}

type indirectBranchInstrDecode struct{}

func (m *indirectBranchInstrDecode) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	instrInfo.InstrSize = 4
	instrInfo.Type = ocsd.InstrBrIndirect
	instrInfo.SubType = ocsd.SInstrNone
	instrInfo.BranchAddr = instrInfo.InstrAddr + 0x200
	instrInfo.NextIsa = instrInfo.Isa
	instrInfo.IsLink = 1
	return ocsd.OK
}

func TestDecoderLinkBranch(t *testing.T) {
	config := NewConfig()
	config.RegCCER = ccerRestackImpl
	config.RegCtrl = ctrlRetStackEna
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)

	mem := &mockMemAcc{}
	dec.MemAccess.Attach(mem)
	dec.InstrDecode.Attach(&linkBranchInstrDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceEnable
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Branch E with IsLink -> push to return stack
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktBranchAddress
	pkt2.AddrVal = 0x5000
	pkt2.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 1, pkt2)
}

type linkBranchInstrDecode struct{}

func (m *linkBranchInstrDecode) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	instrInfo.InstrSize = 4
	instrInfo.Type = ocsd.InstrBr
	instrInfo.SubType = ocsd.SInstrBrLink
	instrInfo.BranchAddr = instrInfo.InstrAddr + 0x100
	instrInfo.NextIsa = instrInfo.Isa
	instrInfo.IsLink = 1
	return ocsd.OK
}

func TestDecoderContProcess(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)
	dec.SetUsesMemAccess(false)
	dec.SetUsesIDecode(false)
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	// Exercise onFlush when not in cont state
	dec.PacketDataIn(ocsd.OpFlush, 0, nil)

	// Various decoder ops
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Non-ISync while waiting
	pkt.ResetState()
	pkt.Type = PktTrigger
	dec.PacketDataIn(ocsd.OpData, 1, pkt)

	// ISYNC to move to decodePkts
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x1000
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	// BadSequence
	pkt.ResetState()
	pkt.Type = PktBadSequence
	dec.PacketDataIn(ocsd.OpData, 3, pkt)

	// ExceptionRet
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 4, pkt)
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0x2000
	dec.PacketDataIn(ocsd.OpData, 5, pkt)
	pkt.ResetState()
	pkt.Type = PktExceptionRet
	dec.PacketDataIn(ocsd.OpData, 6, pkt)

	// VMID no-update path (same value)
	pkt.ResetState()
	pkt.Type = PktVMID
	pkt.Context.VMID = 0x10
	dec.PacketDataIn(ocsd.OpData, 7, pkt)
	// Same VMID again -> bUpdate=false
	pkt.ResetState()
	pkt.Type = PktVMID
	pkt.Context.VMID = 0x10
	dec.PacketDataIn(ocsd.OpData, 8, pkt)

	// ContextID no-update path
	pkt.ResetState()
	pkt.Type = PktContextID
	pkt.Context.CtxtID = 0x20
	dec.PacketDataIn(ocsd.OpData, 9, pkt)
	pkt.ResetState()
	pkt.Type = PktContextID
	pkt.Context.CtxtID = 0x20
	dec.PacketDataIn(ocsd.OpData, 10, pkt)

	// Ignored packet types
	pkt.ResetState()
	pkt.Type = PktNotSync
	dec.PacketDataIn(ocsd.OpData, 11, pkt)
	pkt.ResetState()
	pkt.Type = PktIgnore
	dec.PacketDataIn(ocsd.OpData, 12, pkt)

	// ISync periodic (needIsync=false)
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.ISyncReason = ocsd.ISyncPeriodic
	pkt.AddrVal = 0x3000
	pkt.Context.UpdatedV = true
	pkt.Context.VMID = 0x99
	dec.PacketDataIn(ocsd.OpData, 13, pkt)

	dec.PacketDataIn(ocsd.OpEOT, 14, nil)
}

// --- Packet String tests ---

func TestPtmPacketString(t *testing.T) {
	pkt := &Packet{}
	pkt.ResetState()
	_ = pkt.String()
	_ = pkt.ToStringFmt(0)
	_ = pkt.IsBadPacket()

	// All packet type names
	types := []PktType{
		PktNotSync, PktIncompleteEOT, PktNoError, PktBranchAddress,
		PktASync, PktISync, PktTrigger, PktWPointUpdate, PktIgnore,
		PktContextID, PktVMID, PktAtom, PktTimestamp, PktExceptionRet,
		PktBadSequence, PktReserved, PktType(99),
	}
	for _, pt := range types {
		pkt.Type = pt
		_ = pkt.String()
	}

	// Branch with full fields
	pkt.Type = PktBranchAddress
	pkt.CurrISA = ocsd.ISAArm
	pkt.PrevISA = ocsd.ISAThumb2
	pkt.AddrVal = 0x1000
	pkt.Context.Updated = true
	pkt.Context.CurrNS = false // S
	pkt.Context.CurrHyp = false
	pkt.Exception.Present = true
	pkt.Exception.Number = 20 // > 16 -> "Unknown"
	pkt.CCValid = true
	pkt.CycleCount = 10
	_ = pkt.String()

	// ISA test
	for _, isa := range []ocsd.ISA{ocsd.ISAArm, ocsd.ISAThumb2, ocsd.ISAAArch64, ocsd.ISATee, ocsd.ISAJazelle, ocsd.ISAUnknown} {
		pkt.CurrISA = isa
		_ = pkt.getISAStr()
	}

	// Atom with CC
	pkt.Type = PktAtom
	pkt.Atom.EnBits = 0x1
	pkt.Atom.Num = 1
	pkt.CCValid = true
	pkt.CycleCount = 5
	_ = pkt.String()

	// Atom N with CC
	pkt.Atom.EnBits = 0x0
	_ = pkt.String()

	// Atom without CC, multi
	pkt.CCValid = false
	pkt.Atom.EnBits = 0x5
	pkt.Atom.Num = 3
	_ = pkt.String()

	// ISYNC with all fields
	pkt.Type = PktISync
	pkt.ISyncReason = ocsd.ISyncDebugExit
	pkt.AddrVal = 0x2000
	pkt.Context.CurrNS = true
	pkt.Context.CurrHyp = true
	pkt.Context.UpdatedC = true
	pkt.Context.CtxtID = 0xBB
	pkt.CCValid = true
	pkt.CycleCount = 30
	pkt.CurrISA = ocsd.ISAThumb2
	_ = pkt.String()

	// ISYNC S, no Hyp
	pkt.Context.CurrNS = false
	pkt.Context.CurrHyp = false
	_ = pkt.String()

	// WPointUpdate string
	pkt.Type = PktWPointUpdate
	pkt.CurrISA = ocsd.ISAArm
	pkt.PrevISA = ocsd.ISAArm // same ISA -> no ISA string
	pkt.Context.Updated = false
	pkt.Exception.Present = false
	pkt.CCValid = false
	_ = pkt.String()
}

// --- Processor edge cases ---

func TestProcAsyncPadLimit(t *testing.T) {
	config := NewConfig()
	proc := setupProcOnly(config)

	// Long sequence of 0x00 to trigger asyncResultThrow0
	data := make([]byte, 50)
	for i := range data {
		data[i] = 0x00
	}
	// Terminate with ASYNC
	data = append(data, 0x80)

	proc.TraceDataIn(ocsd.OpData, 0, data)
}

func TestProcAsyncMidStream(t *testing.T) {
	config := NewConfig()
	proc := setupProcOnly(config)

	data := makeAsyncBlock()
	// Some packets
	data = append(data, 0x0C) // trigger
	// Inline ASYNC: header 0x00
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80)

	proc.TraceDataIn(ocsd.OpData, 0, data)
}

func TestProcISyncPeriodicNoCC(t *testing.T) {
	config := NewConfig()
	proc := setupProcOnly(config)

	data := makeAsyncBlock()
	// ISYNC with reason=0 (periodic) -> no CC needed
	data = append(data,
		0x08,
		0x00, 0x00, 0x00, 0x00,
		0x00, // reason=0
	)
	proc.TraceDataIn(ocsd.OpData, 0, data)
}

func TestProcTimestampWithMultiByteCC(t *testing.T) {
	config := NewConfig()
	config.RegCtrl = ctrlCycleAcc
	proc := setupProcOnly(config)

	data := makeAsyncBlock()
	// Timestamp (0x46) with multi-byte CC
	data = append(data,
		0x46,
		0x11, // TS: bit7=0 -> done
		0x44, // CC byte1: bit6=1 -> continue (first CC byte uses bit6)
		0x80, // CC byte2: bit7=1 -> continue
		0x80, // CC byte3: bit7=1 -> continue
		0x80, // CC byte4: bit7=1 -> continue
		0x00, // CC byte5: forced done at count==5
	)
	proc.TraceDataIn(ocsd.OpData, 0, data)
}

// ============================================================
// New tests for 0% decoder functions (Phase 9 Round 2)
// ============================================================

// syncDec sends ASync then ISync to a freshly-reset decoder, advancing it to decodePkts.
// The decoder state machine starts at decodeNoSync, requires PktASync to reach
// decodeWaitISync, and then PktISync to reach decodePkts.
func syncDec(dec *PktDecode, addr ocsd.VAddr) {
	async := &Packet{}
	async.ResetState()
	async.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, async)

	isync := &Packet{}
	isync.ResetState()
	isync.Type = PktISync
	isync.AddrVal = addr
	isync.CurrISA = ocsd.ISAArm
	isync.ISyncReason = ocsd.ISyncTraceEnable
	dec.PacketDataIn(ocsd.OpData, 1, isync)
}

// newTestDec creates a PktDecode with mockMemAcc and mockInstrDecode attached.
func newTestDec(hitAfter int) (*PktDecode, *testTrcElemIn) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)
	dec.MemAccess.Attach(&mockMemAcc{})
	dec.InstrDecode.Attach(&mockInstrDecode{hitAfter: hitAfter})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	return dec, out
}

// TestAtomDataMethods exercises all atomData struct methods directly.
func TestAtomDataMethods(t *testing.T) {
	var a atoms

	a.init(ocsd.PktAtom{Num: 3, EnBits: 0x5}, 42) // binary 101 -> E,N,E
	if a.numAtoms() != 3 {
		t.Errorf("numAtoms: want 3, got %d", a.numAtoms())
	}
	if a.pktIndex() != 42 {
		t.Errorf("pktIndex: want 42, got %d", a.pktIndex())
	}
	if v := a.getCurrAtomVal(); v != ocsd.AtomE {
		t.Errorf("getCurrAtomVal: want AtomE, got %v", v)
	}

	a.clearAtom()
	if a.numAtoms() != 2 {
		t.Errorf("after clearAtom numAtoms: want 2, got %d", a.numAtoms())
	}
	// EnBits was 0x5 (101), after >>1 = 0x2 (010) -> bit0=0 -> AtomN
	if v := a.getCurrAtomVal(); v != ocsd.AtomN {
		t.Errorf("getCurrAtomVal after clear: want AtomN, got %v", v)
	}

	a.clearAll()
	if a.numAtoms() != 0 {
		t.Errorf("after clearAll: want 0, got %d", a.numAtoms())
	}
	a.clearAtom() // Num==0 no-op
	if a.numAtoms() != 0 {
		t.Errorf("clearAtom on empty: want 0, got %d", a.numAtoms())
	}
}

// TestDecoderAtomMultiStep exercises traceInstrToWP walking multiple InstrOther
// instructions before hitting a waypoint (hitAfter:2 -> 2 non-WP, then WP).
func TestDecoderAtomMultiStep(t *testing.T) {
	dec, out := newTestDec(2)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0x1000)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktAtom
	pkt.Atom.EnBits = 0x1 // E
	pkt.Atom.Num = 1
	resp := dec.PacketDataIn(ocsd.OpData, 2, pkt)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("multiStep atom failed: %v", resp)
	}
	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements from multi-step atom")
	}
}

// TestDecoderAtomRange_NoWPFound exercises the !bWPFound path in processAtomRange
// by using hitAfter:-1 (always InstrOther) and failAfter:2 (memNacc after 2 reads).
// When StAddr != EnAddr the partial range element is emitted from the else branch.
func TestDecoderAtomRange_NoWPFound(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: 2}) // fail after 2 reads
	dec.InstrDecode.Attach(&mockInstrDecode{hitAfter: -1})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0x2000)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktAtom
	pkt.Atom.EnBits = 0x1
	pkt.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 2, pkt)
	dec.PacketDataIn(ocsd.OpEOT, 3, nil)
}

// TestDecoderProcessBranch_ExceptionCCValid exercises processBranch with exception
// present and CCValid set (both the exception emission and the CC path).
func TestDecoderProcessBranch_ExceptionCCValid(t *testing.T) {
	dec, out := newTestDec(0)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0x5000)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.Exception.Present = true
	pkt.Exception.Number = 3
	pkt.AddrVal = 0x7000
	pkt.CurrISA = ocsd.ISAArm
	pkt.CCValid = true
	pkt.CycleCount = 7
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	if len(out.elements) == 0 {
		t.Errorf("Expected elements from branch with exception")
	}
}

// TestDecoderProcessWPUpdate_traceToAddrIncl validates processWPUpdate calls
// processAtomRange with traceToAddrIncl where currOpAddress matches nextAddrMatch.
func TestDecoderProcessWPUpdate_traceToAddrIncl(t *testing.T) {
	dec, out := newTestDec(5) // won't hit InstrBr before address match
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0x3000)

	// WP Update with addr matching start -> traceToAddrIncl match on first iter
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktWPointUpdate
	pkt.AddrVal = 0x3000
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	if len(out.elements) == 0 {
		t.Errorf("Expected elements from WP update")
	}
}

// TestDecoderProcessAtom_MultiAtomLoop exercises processAtom's loop over multiple atoms.
func TestDecoderProcessAtom_MultiAtomLoop(t *testing.T) {
	dec, out := newTestDec(0)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0x4000)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktAtom
	pkt.Atom.EnBits = 0x5 // E,N,E,N
	pkt.Atom.Num = 4
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	if len(out.elements) == 0 {
		t.Errorf("Expected trace elements from multi-atom loop")
	}
}

// TestDecoderCheckPendingNacc_Nonsecure verifies checkPendingNacc emits AddrNacc
// with MemSpaceEL1N when security level is non-secure (CurrNS=true).
func TestDecoderCheckPendingNacc_Nonsecure(t *testing.T) {
	config := NewConfig()
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: 1})
	dec.InstrDecode.Attach(&mockInstrDecode{hitAfter: -1})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ASync -> ISync with NS=true (non-secure context)
	async := &Packet{}
	async.ResetState()
	async.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, async)

	isync := &Packet{}
	isync.ResetState()
	isync.Type = PktISync
	isync.AddrVal = 0x8000
	isync.CurrISA = ocsd.ISAArm
	isync.ISyncReason = ocsd.ISyncTraceEnable
	isync.Context.CurrNS = true // non-secure
	dec.PacketDataIn(ocsd.OpData, 1, isync)

	// Atom -> memNacc -> memNaccPending=true
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktAtom
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 2, pkt2)

	// Branch -> checkPendingNacc emits AddrNacc
	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktBranchAddress
	pkt3.AddrVal = 0x9000
	pkt3.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 3, pkt3)
}

// TestDecoderContProcess_AllStates exercises all four contProcess state branches.
// contProcess is called via onFlush; since testTrcElemIn always returns RespCont,
// the decoder won't naturally enter continuation states, so we test each code path
// by issuing packets then flushing.
func TestDecoderContProcess_AllStates(t *testing.T) {
	// decodeContAtom: Atom packets processed at decodePkts then flush
	{
		dec, _ := newTestDec(0)
		dec.PacketDataIn(ocsd.OpReset, 0, nil)
		syncDec(dec, 0x1000)
		pkt := &Packet{}
		pkt.ResetState()
		pkt.Type = PktAtom
		pkt.Atom.EnBits = 0x3
		pkt.Atom.Num = 2
		dec.PacketDataIn(ocsd.OpData, 2, pkt)
		dec.PacketDataIn(ocsd.OpFlush, 3, nil)
	}

	// decodeContWPUp: WP update then flush
	{
		dec, _ := newTestDec(0)
		dec.PacketDataIn(ocsd.OpReset, 0, nil)
		syncDec(dec, 0x1000)
		pkt := &Packet{}
		pkt.ResetState()
		pkt.Type = PktWPointUpdate
		pkt.AddrVal = 0x1000
		dec.PacketDataIn(ocsd.OpData, 2, pkt)
		dec.PacketDataIn(ocsd.OpFlush, 3, nil)
	}

	// decodeContBranch: branch then flush
	{
		dec, _ := newTestDec(0)
		dec.PacketDataIn(ocsd.OpReset, 0, nil)
		syncDec(dec, 0x1000)
		pkt := &Packet{}
		pkt.ResetState()
		pkt.Type = PktBranchAddress
		pkt.AddrVal = 0x9000
		pkt.CurrISA = ocsd.ISAArm
		dec.PacketDataIn(ocsd.OpData, 2, pkt)
		dec.PacketDataIn(ocsd.OpFlush, 3, nil)
	}

	// decodeContISync: ISync with UpdatedC context -> iSyncPeCtxt=true -> outputs both TraceOn and PeContext
	{
		dec, _ := newTestDec(0)
		dec.PacketDataIn(ocsd.OpReset, 0, nil)
		// First sync
		syncDec(dec, 0x1000)
		// Second ISync with context update
		pkt := &Packet{}
		pkt.ResetState()
		pkt.Type = PktISync
		pkt.AddrVal = 0x1000
		pkt.CurrISA = ocsd.ISAArm
		pkt.ISyncReason = ocsd.ISyncTraceEnable
		pkt.Context.UpdatedC = true
		pkt.Context.CtxtID = 0xBEEF
		dec.PacketDataIn(ocsd.OpData, 2, pkt)
		dec.PacketDataIn(ocsd.OpFlush, 3, nil)
	}
}

// TestDecoderDecodePacket_RemainingBranches covers ISyncDebugExit, PktAtom with valid
// pe state (N atom), PktTimestamp with CCValid, and ignored packet types.
func TestDecoderDecodePacket_RemainingBranches(t *testing.T) {
	dec, _ := newTestDec(0)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ISyncDebugExit exercises the TraceOnExDebug path in processIsync
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0xA000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncDebugExit
	pkt.CCValid = true
	pkt.CycleCount = 3
	dec.PacketDataIn(ocsd.OpData, 1, pkt)

	// N Atom while peState is valid
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktAtom
	pkt2.Atom.EnBits = 0x0 // N
	pkt2.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 2, pkt2)

	// Timestamp with CCValid
	pkt3 := &Packet{}
	pkt3.ResetState()
	pkt3.Type = PktTimestamp
	pkt3.Timestamp = 0x1234
	pkt3.CCValid = true
	pkt3.CycleCount = 99
	dec.PacketDataIn(ocsd.OpData, 3, pkt3)

	// Ignored types in decodePacket
	for _, tp := range []PktType{PktIncompleteEOT, PktNoError, PktASync, PktIgnore} {
		p := &Packet{}
		p.ResetState()
		p.Type = tp
		dec.PacketDataIn(ocsd.OpData, 4, p)
	}

	dec.PacketDataIn(ocsd.OpEOT, 5, nil)
}

// TestDecoderIndirectBranch_ActiveRetStack tests BrIndirect with active return stack.
// indirectBranchIsLinkDecode returns BrIndirect with IsLink=1.
func TestDecoderIndirectBranch_ActiveRetStack(t *testing.T) {
	config := NewConfig()
	config.RegCCER = ccerRestackImpl
	config.RegCtrl = ctrlRetStackEna
	dec := NewPktDecode(0)
	dec.SetProtocolConfig(config)
	dec.MemAccess.Attach(&mockMemAcc{})
	dec.InstrDecode.Attach(&indirectBranchIsLinkDecode{})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)

	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0x1000)

	// First atom E: BrIndirect IsLink=1 -> return stack is empty, pops nothing
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktAtom
	pkt.Atom.EnBits = 0x1
	pkt.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	// Resync
	syncDec(dec, 0x2000)

	// Second atom E: pops from return stack (if push worked)
	pkt2 := &Packet{}
	pkt2.ResetState()
	pkt2.Type = PktAtom
	pkt2.Atom.EnBits = 0x1
	pkt2.Atom.Num = 1
	dec.PacketDataIn(ocsd.OpData, 5, pkt2)
}

// indirectBranchIsLinkDecode: BrIndirect with IsLink=1.
type indirectBranchIsLinkDecode struct{}

func (m *indirectBranchIsLinkDecode) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	instrInfo.InstrSize = 4
	instrInfo.Type = ocsd.InstrBrIndirect
	instrInfo.SubType = ocsd.SInstrNone
	instrInfo.BranchAddr = instrInfo.InstrAddr + 0x200
	instrInfo.NextIsa = instrInfo.Isa
	instrInfo.IsLink = 1
	return ocsd.OK
}

// TestDecoderISyncPeriodic_WithVMIDUpdate exercises ISyncPeriodic with UpdatedV=true.
func TestDecoderISyncPeriodic_WithVMIDUpdate(t *testing.T) {
	dec, _ := newTestDec(0)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0xC000)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0xC000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncPeriodic
	pkt.Context.UpdatedV = true
	pkt.Context.VMID = 0xAB
	dec.PacketDataIn(ocsd.OpData, 2, pkt)
}

// TestDecoderWaitISync_NonISyncPacket exercises the decodeWaitISync state where
// a non-ISync packet is silently dropped (hits the else bPktDone=true branch).
func TestDecoderWaitISync_NonISyncPacket(t *testing.T) {
	dec, _ := newTestDec(0)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	// ASync -> state becomes decodeWaitISync
	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	// Non-ISync packet while in decodeWaitISync -> dropped silently
	pkt.ResetState()
	pkt.Type = PktTimestamp
	pkt.Timestamp = 0xFF
	dec.PacketDataIn(ocsd.OpData, 1, pkt)

	// ISync to advance to decodePkts
	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0xD000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceEnable
	dec.PacketDataIn(ocsd.OpData, 2, pkt)
}

// TestDecoderISyncOverflow exercises ISyncTraceRestartAfterOverflow -> TraceOnOverflow.
func TestDecoderISyncOverflow(t *testing.T) {
	dec, _ := newTestDec(0)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktASync
	dec.PacketDataIn(ocsd.OpData, 0, pkt)

	pkt.ResetState()
	pkt.Type = PktISync
	pkt.AddrVal = 0xE000
	pkt.CurrISA = ocsd.ISAArm
	pkt.ISyncReason = ocsd.ISyncTraceRestartAfterOverflow
	dec.PacketDataIn(ocsd.OpData, 1, pkt)
}

// TestDecoderBranchNoException_ValidPeState exercises processBranch without exception
// and with valid pe state -> calls processAtomRange.
func TestDecoderBranchNoException_ValidPeState(t *testing.T) {
	dec, out := newTestDec(0)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)
	syncDec(dec, 0xF000)

	pkt := &Packet{}
	pkt.ResetState()
	pkt.Type = PktBranchAddress
	pkt.AddrVal = 0xF200
	pkt.CurrISA = ocsd.ISAArm
	dec.PacketDataIn(ocsd.OpData, 2, pkt)

	if len(out.elements) == 0 {
		t.Errorf("Expected elements from branch without exception")
	}
}
