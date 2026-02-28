package etmv3

import (
	"opencsd/internal/ocsd"
)

// --- Mocks ---
type testTrcElemIn struct {
	elements []ocsd.TraceElement
}

func (t *testTrcElemIn) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	t.elements = append(t.elements, *elem)
	return ocsd.RespCont
}

type mockMemAcc struct {
	failAfter int
	calls     int
}

func (m *mockMemAcc) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	m.calls++
	if m.failAfter >= 0 && m.calls > m.failAfter {
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

type mockInstrDecodeWaypoint struct {
	returnType ocsd.InstrType
	callCount  int
}

func (m *mockInstrDecodeWaypoint) DecodeInstruction(info *ocsd.InstrInfo) ocsd.Err {
	m.callCount++
	info.InstrSize = 4
	info.NextIsa = info.Isa
	info.SubType = ocsd.SInstrNone
	info.Type = m.returnType
	if m.returnType == ocsd.InstrBr {
		info.BranchAddr = info.InstrAddr + 0x10
	}
	return ocsd.OK
}

type noopPktSinkV3 struct{}

func (s *noopPktSinkV3) PacketDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, pkt *Packet) ocsd.DatapathResp {
	return ocsd.RespCont
}

func setupProcDec(config *Config) (*PktProc, *PktDecode, *testTrcElemIn) {
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	dec := manager.CreatePktDecode(0, config).(*PktDecode)
	proc.PktOutI.Attach(dec)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1})
	dec.InstrDecode.Attach(&mockInstrDecode{hitAfter: -1})
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	return proc, dec, out
}
