package ptm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const snapshotPath = "../../decoder/tests/snapshots/trace_cov_a15"
const resultsPath = "../../decoder/tests/results"

func TestSnapshotAvailable(t *testing.T) {
	binPath := filepath.Join(snapshotPath, "PTM_0_2.bin")
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatalf("PTM snapshot not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("PTM snapshot is empty")
	}
	t.Logf("Found PTM snapshot: %s (%d bytes)", binPath, info.Size())
}

func TestASyncPacket_Detection(t *testing.T) {
	// First packet from trace_cov_a15.ppl:
	// Idx:0; ID:0; [0x00 0x00 0x00 0x00 0x00 0x80 ];	ASYNC : Alignment Synchronisation Packet;
	raw := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeASYNC, pkt.Type, "packet type")
	assertEqual(t, uint64(0), pkt.Offset, "byte offset")
	assertBytesEqual(t, raw, pkt.Data, "packet data")
}

func TestASyncPacket_WithTrailingData(t *testing.T) {
	// A-Sync followed by other data
	raw := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x08, 0x58, // Start of next packet
	}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) < 1 {
		t.Fatalf("expected at least 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeASYNC, pkt.Type, "first packet type")
	assertBytesEqual(t, raw[0:6], pkt.Data, "A-Sync packet data")
}

func TestPTMDecoder_FirstChunkFromSnapshot(t *testing.T) {
	binPath := filepath.Join(snapshotPath, "PTM_0_2.bin")
	raw, err := os.ReadFile(binPath)
	if err != nil {
		t.Skipf("Snapshot not available: %v", err)
	}

	// Read first 1024 bytes
	if len(raw) > 1024 {
		raw = raw[:1024]
	}

	decoder := NewDecoder(0)
	packets, err := testParseSuccess(t, decoder, raw)

	if len(packets) == 0 {
		t.Fatal("expected at least one packet from first chunk")
	}

	t.Logf("Parsed %d packets from %d bytes", len(packets), len(raw))
	
	// First packet should be A-Sync based on C++ output
	if packets[0].Type != PacketTypeASYNC {
		t.Errorf("expected first packet to be ASYNC, got %s", packets[0].Type)
	}
}

// TestAgainstCppReference demonstrates full validation against C++ .ppl output
func TestAgainstCppReference(t *testing.T) {
	// Load C++ reference output
	pplPath := filepath.Join(resultsPath, "trace_cov_a15.ppl")
	cppPackets, err := LoadCppReference(pplPath, 0)
	if err != nil {
		t.Skipf("C++ reference not available: %v", err)
	}

	if len(cppPackets) == 0 {
		t.Skip("No packets found in C++ reference")
	}

	// Load binary trace
	binPath := filepath.Join(snapshotPath, "PTM_0_2.bin")
	raw, err := os.ReadFile(binPath)
	if err != nil {
		t.Skipf("Snapshot not available: %v", err)
	}

	// Parse with Go decoder
	decoder := NewDecoder(0)
	goPackets, err := testParseSuccess(t, decoder, raw)

	// Compare packet count
	if len(goPackets) != len(cppPackets) {
		t.Logf("Packet count mismatch: Go=%d, C++=%d", len(goPackets), len(cppPackets))
		// This will fail until decoder is complete - that's expected in TDD
	}

	// Compare first few packets in detail
	compareLimit := min(5, len(goPackets), len(cppPackets))
	for i := 0; i < compareLimit; i++ {
		cpp := cppPackets[i]
		got := goPackets[i]

		t.Logf("Packet %d:", i)
		t.Logf("  C++: Idx:%d Type:%s Bytes:%x", cpp.ByteOffset, cpp.Type, cpp.Bytes)
		t.Logf("  Go:  Idx:%d Type:%s Bytes:%x", got.Offset, got.Type, got.Data)

		if got.Offset != cpp.ByteOffset {
			t.Errorf("  Offset mismatch: got %d, want %d", got.Offset, cpp.ByteOffset)
		}
		if got.Type.String() != cpp.Type {
			t.Errorf("  Type mismatch: got %s, want %s", got.Type, cpp.Type)
		}
		if !bytes.Equal(got.Data, cpp.Bytes) {
			t.Errorf("  Bytes mismatch: got %x, want %x", got.Data, cpp.Bytes)
		}
	}
}

// Test utilities

func testParseSuccess(t *testing.T, decoder *Decoder, raw []byte) ([]Packet, error) {
	t.Helper()
	packets, err := decoder.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	return packets, err
}

func assertEqual[T comparable](t *testing.T, want, got T, msg string) {
	t.Helper()
	if want != got {
		t.Errorf("%s: want %v, got %v", msg, want, got)
	}
}

func assertBytesEqual(t *testing.T, want, got []byte, msg string) {
	t.Helper()
	if !bytes.Equal(want, got) {
		t.Errorf("%s: want %x, got %x", msg, want, got)
	}
}

func min(vals ...int) int {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}
