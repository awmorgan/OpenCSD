package etmv3

import (
	"errors"
	"testing"

	"opencsd/internal/common"
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
	proc, dec, err := NewConfiguredPipeline(0, config)
	if err != nil {
		panic(err)
	}
	dec.SetMemAccess(&mockMemAcc{failAfter: -1, hitAfter: -1})
	dec.SetInstrDecode(idec.NewDecoder())
	out := &testTrcElemIn{}
	dec.SetTraceElemOut(out)
	return proc, dec, out
}

func TestETMv3TypedConstructors(t *testing.T) {
	config := &Config{}
	proc, err := NewConfiguredPktProc(1, config)
	if err != nil || proc == nil || proc.Config != config {
		t.Fatalf("NewConfiguredPktProc failed: proc=%v err=%v", proc, err)
	}

	dec, err := NewConfiguredPktDecode(2, config)
	if err != nil || dec == nil || dec.Config != config {
		t.Fatalf("NewConfiguredPktDecode failed: dec=%v err=%v", dec, err)
	}

	proc, dec, err = NewConfiguredPipeline(3, config)
	if err != nil || proc == nil || dec == nil {
		t.Fatalf("NewConfiguredPipeline failed: proc=%v dec=%v err=%v", proc, dec, err)
	}
	if got := proc.PktOut(); got != dec {
		t.Fatal("expected pipeline constructor to wire processor output to decoder")
	}

	if proc, err := NewConfiguredPktProc(0, nil); proc != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config proc constructor failure, got proc=%v err=%v", proc, err)
	}
	if dec, err := NewConfiguredPktDecode(0, nil); dec != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config decode constructor failure, got dec=%v err=%v", dec, err)
	}
}

func mustNewConfiguredPktProc(tb testing.TB, config *Config) *PktProc {
	tb.Helper()
	proc, err := NewConfiguredPktProc(0, config)
	if err != nil {
		tb.Fatalf("NewConfiguredPktProc failed: %v", err)
	}
	return proc
}

func mustNewConfiguredPktDecode(tb testing.TB, config *Config) *PktDecode {
	tb.Helper()
	dec, err := NewConfiguredPktDecode(0, config)
	if err != nil {
		tb.Fatalf("NewConfiguredPktDecode failed: %v", err)
	}
	return dec
}

func isErrorCode(err error, code ocsd.Err) bool {
	if err == nil {
		return false
	}
	var libErr *common.Error
	if !errors.As(err, &libErr) {
		return false
	}
	return libErr.Code == code
}
