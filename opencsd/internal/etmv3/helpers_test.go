package etmv3

import (
	"errors"
	"io"
	"testing"

	"opencsd/internal/idec"
	"opencsd/internal/ocsd"
)

// --- Mocks ---
type mockMemAcc struct {
	failAfter int
	calls     int
	hitAfter  int
	instrType ocsd.InstrType // type to emit at waypoint
}

func (m *mockMemAcc) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	m.calls++
	if m.failAfter >= 0 && m.calls > m.failAfter {
		return 0, nil, nil
	}

	isHit := m.hitAfter >= 0 && m.calls > m.hitAfter

	if isHit {
		switch m.instrType {
		case ocsd.InstrBrIndirect:
			return reqBytes, []byte{0x1E, 0xFF, 0x2F, 0xE1}, nil // BX LR (0xE12FFF1E - unconditional)
		case ocsd.InstrOther:
			return reqBytes, []byte{0x00, 0x00, 0x80, 0xE0}, nil // ADD R0, R0, R0
		}
		// Default to branch
		return reqBytes, []byte{0x00, 0x00, 0x00, 0xEA}, nil // B (0xEA000000)
	}

	return reqBytes, []byte{0x00, 0x00, 0x80, 0xE0}, nil // ADD R0, R0, R0
}

func (m *mockMemAcc) InvalidateMemAccCache(csTraceID uint8) {}

func TestETMv3TypedConstructors(t *testing.T) {
	config := &Config{}
	mem := &mockMemAcc{failAfter: -1}
	instr := idec.NewDecoder()
	proc, err := NewConfiguredPktProc(1, config)
	if err != nil || proc == nil || proc.Config != config {
		t.Fatalf("NewConfiguredPktProc failed: proc=%v err=%v", proc, err)
	}

	dec, err := NewConfiguredPktDecode(2, config, mem, instr)
	if err != nil || dec == nil || dec.Config != config {
		t.Fatalf("NewConfiguredPktDecode failed: dec=%v err=%v", dec, err)
	}

	proc, dec, err = NewConfiguredPipeline(3, config, &mockMemAcc{failAfter: -1}, idec.NewDecoder())
	if err != nil || proc == nil || dec == nil {
		t.Fatalf("NewConfiguredPipeline failed: proc=%v dec=%v err=%v", proc, dec, err)
	}
	if dec.Source != proc {
		t.Fatal("expected pipeline constructor to wire processor as decoder source")
	}

	if proc, err := NewConfiguredPktProc(0, nil); proc != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config proc constructor failure, got proc=%v err=%v", proc, err)
	}
	if dec, err := NewConfiguredPktDecode(0, nil, mem, instr); dec != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config decode constructor failure, got dec=%v err=%v", dec, err)
	}
	if dec, err := NewConfiguredPktDecode(0, config, nil, instr); dec != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-mem decode constructor failure, got dec=%v err=%v", dec, err)
	}
	if dec, err := NewConfiguredPktDecode(0, config, mem, nil); dec != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-decoder constructor failure, got dec=%v err=%v", dec, err)
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
	dec, err := NewPktDecode(config, &mockMemAcc{failAfter: -1}, idec.NewDecoder(), nil, nil)
	if err != nil {
		tb.Fatalf("NewConfiguredPktDecode failed: %v", err)
	}
	return dec
}

func isErrorCode(err error, code error) bool {
	return errors.Is(err, code)
}

func writeDecodedPacket(dec *PktDecode, indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	if pktIn == nil {
		return ocsd.ErrInvalidParamVal
	}
	dec.CurrPacketIn = pktIn
	dec.IndexCurrPkt = indexSOP
	err := dec.ProcessPacket()
	dec.flushOutputElements()
	return err
}

func drainDecodedElements(t *testing.T, dec *PktDecode) []ocsd.TraceElement {
	t.Helper()
	elems := make([]ocsd.TraceElement, 0)
	for {
		elem, err := dec.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decoder next failed: %v", err)
		}
		elems = append(elems, *elem)
	}
	return elems
}
