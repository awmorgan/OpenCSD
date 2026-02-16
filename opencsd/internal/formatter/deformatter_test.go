package formatter

import (
	"testing"

	"opencsd/internal/common"
)

type mockReceiver struct {
	data []byte
}

func (m *mockReceiver) TraceDataIn(op common.DataPathOp, index int64, data []byte) (common.DataPathResp, int, error) {
	if op == common.OpData {
		m.data = append(m.data, data...)
	}
	return common.RespCont, len(data), nil
}

func TestDeformatter(t *testing.T) {
	d := NewDeformatter()
	r1 := &mockReceiver{}
	r2 := &mockReceiver{}
	d.Attach(0x10, r1)
	d.Attach(0x20, r2)

	// Create a frame:
	// Byte 0: ID change to 0x10 -> (0x10 << 1) | 1 = 0x21
	// Byte 1: Data 0xAA
	// Byte 2: Data 0xBB (even, LSB 0 in frame, flag bit 1 for bit 0) -> 0xBA in frame, flag bit 1=1
	// Byte 3: Data 0xCC
	// ...
	// Byte 15: Flags. Bit 1 (for byte 2) = 1.
	frame := make([]byte, 16)
	frame[0] = 0x21 // ID -> 0x10
	frame[1] = 0xAA
	frame[2] = 0xBA // Data 0xBA | flag(1) = 0xBB
	frame[3] = 0xCC
	frame[15] = 0x02 // Bit 1 is set for Byte 2

	_, _, err := d.TraceDataIn(common.OpData, 0, frame)
	if err != nil {
		t.Fatalf("TraceDataIn failed: %v", err)
	}

	if len(r1.data) < 3 || r1.data[0] != 0xAA || r1.data[1] != 0xBB || r1.data[2] != 0xCC {
		t.Errorf("r1 data mismatch: got %v, want starting with [0xAA 0xBB 0xCC]", r1.data)
	}

	// Test ID change mid-frame
	frame2 := make([]byte, 16)
	frame2[0] = 0x41  // ID -> 0x20
	frame2[1] = 0xDD  // Data for 0x20
	frame2[15] = 0x00 // No flags

	_, _, err = d.TraceDataIn(common.OpData, 16, frame2)
	if err != nil {
		t.Fatalf("TraceDataIn failed: %v", err)
	}

	if len(r2.data) == 0 || r2.data[0] != 0xDD {
		t.Errorf("r2 data mismatch: got %x, want [DD]", r2.data)
	}
}
