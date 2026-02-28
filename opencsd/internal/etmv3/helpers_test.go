package etmv3

import (
	"opencsd/internal/idec"
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
	hitAfter  int
	instrType ocsd.InstrType // type to emit at waypoint
}

func (m *mockMemAcc) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	m.calls++
	if m.failAfter >= 0 && m.calls > m.failAfter {
		return 0, nil, ocsd.OK
	}

	isHit := m.hitAfter >= 0 && m.calls > m.hitAfter

	if isHit {
		if m.instrType == ocsd.InstrBrIndirect {
			return reqBytes, []byte{0x1E, 0xFF, 0x2F, 0xE1}, ocsd.OK // BX LR (0xE12FFF1E - unconditional)
		} else if m.instrType == ocsd.InstrOther {
			return reqBytes, []byte{0x00, 0x00, 0x80, 0xE0}, ocsd.OK // ADD R0, R0, R0
		}
		// Default to branch
		return reqBytes, []byte{0x00, 0x00, 0x00, 0xEA}, ocsd.OK // B (0xEA000000)
	}

	return reqBytes, []byte{0x00, 0x00, 0x80, 0xE0}, ocsd.OK // ADD R0, R0, R0
}

func (m *mockMemAcc) InvalidateMemAccCache(csTraceID uint8) {}

type noopPktSinkV3 struct{}

func (s *noopPktSinkV3) PacketDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, pkt *Packet) ocsd.DatapathResp {
	return ocsd.RespCont
}

func setupProcDec(config *Config) (*PktProc, *PktDecode, *testTrcElemIn) {
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config).(*PktProc)
	dec := manager.CreatePktDecode(0, config).(*PktDecode)
	proc.PktOutI.Attach(dec)
	dec.MemAccess.Attach(&mockMemAcc{failAfter: -1, hitAfter: -1})
	dec.InstrDecode.Attach(idec.NewDecoder())
	out := &testTrcElemIn{}
	dec.TraceElemOut.Attach(out)
	return proc, dec, out
}
