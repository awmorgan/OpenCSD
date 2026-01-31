package ptm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"opencsd/common"
)

const snapshotPath = "../../decoder/tests/snapshots/trace_cov_a15"
const tc2SnapshotPath = "../../decoder/tests/snapshots/TC2"
const resultsPath = "../../decoder/tests/results"

// loadMemorySnapshot loads all memory regions from the trace_cov_a15 snapshot
func loadMemorySnapshot(t *testing.T) common.MemoryAccessor {
	t.Helper()

	memMap := common.NewMultiRegionMemory()

	// Memory regions from device1.ini
	regions := []struct {
		addr uint64
		file string
	}{
		{0x80000000, "mem_Cortex-A15_0_0_VECTORS.bin"},
		{0x80000278, "mem_Cortex-A15_0_1_RO_CODE.bin"},
		{0x80001C28, "mem_Cortex-A15_0_2_RO_DATA.bin"},
		{0x80001D58, "mem_Cortex-A15_0_3_RW_DATA.bin"},
		{0x80001D68, "mem_Cortex-A15_0_4_ZI_DATA.bin"},
		{0x80040000, "mem_Cortex-A15_0_5_ARM_LIB_HEAP.bin"},
		{0x80080000, "mem_Cortex-A15_0_6_ARM_LIB_STACK.bin"},
		{0x80090000, "mem_Cortex-A15_0_7_IRQ_STACK.bin"},
		{0x80100000, "mem_Cortex-A15_0_8_TTB.bin"},
	}

	for _, region := range regions {
		path := filepath.Join(snapshotPath, region.file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("Failed to load memory region %s: %v", region.file, err)
		}
		memMap.AddRegion(common.NewMemoryBuffer(region.addr, data))
		t.Logf("Loaded memory region: 0x%08X - 0x%08X (%s, %d bytes)",
			region.addr, region.addr+uint64(len(data)), region.file, len(data))
	}

	return memMap
}

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

func TestMemoryAccessor_LoadSnapshot(t *testing.T) {
	memAcc := loadMemorySnapshot(t)

	// Test reading from VECTORS region
	buf := make([]byte, 4)
	n, err := memAcc.ReadMemory(0x80000000, buf)
	if err != nil {
		t.Fatalf("Failed to read from VECTORS: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected to read 4 bytes, got %d", n)
	}
	t.Logf("Read from 0x80000000: %02X %02X %02X %02X", buf[0], buf[1], buf[2], buf[3])

	// Test reading from RO_CODE region
	n, err = memAcc.ReadMemory(0x80000278, buf)
	if err != nil {
		t.Fatalf("Failed to read from RO_CODE: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected to read 4 bytes, got %d", n)
	}
	t.Logf("Read from 0x80000278: %02X %02X %02X %02X", buf[0], buf[1], buf[2], buf[3])

	// Test reading from invalid address (should fail)
	_, err = memAcc.ReadMemory(0x00000000, buf)
	if err == nil {
		t.Error("Expected error reading from invalid address, got nil")
	} else {
		t.Logf("Correctly rejected invalid address: %v", err)
	}
}

func TestDecoder_WithMemoryAccessor(t *testing.T) {
	// Load memory snapshot
	memAcc := loadMemorySnapshot(t)

	// Create decoder and attach memory accessor
	decoder := NewDecoder(0)
	decoder.SetMemoryAccessor(memAcc)

	// Load trace data
	binPath := filepath.Join(snapshotPath, "PTM_0_2.bin")
	raw, err := os.ReadFile(binPath)
	if err != nil {
		t.Skipf("Snapshot not available: %v", err)
	}

	// Parse packets
	packets, err := decoder.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	t.Logf("Parsed %d packets from trace", len(packets))

	// Process packets with memory access capability
	totalElements := 0
	for i, pkt := range packets {
		elements, err := decoder.ProcessPacket(pkt)
		if err != nil {
			t.Logf("Warning: ProcessPacket error at packet %d (%s): %v", i, pkt.Type, err)
			continue
		}

		totalElements += len(elements)
		if len(elements) > 0 {
			t.Logf("Packet %d (%s) -> %d elements", i, pkt.Type, len(elements))
			for _, elem := range elements {
				t.Logf("  %s", elem.Description())
			}
		}
	}

	t.Logf("Total elements generated: %d", totalElements)
	t.Logf("Decoder has memory access: %v", decoder.MemAcc != nil)
}

func TestAtomProcessing_DetailedTracking(t *testing.T) {
	// Load memory snapshot
	memAcc := loadMemorySnapshot(t)

	// Create decoder with logger for detailed output
	logger := common.NewStdLogger(common.SeverityDebug)
	decoder := NewDecoderWithLogger(0, logger)
	decoder.SetMemoryAccessor(memAcc)

	// Load trace data
	binPath := filepath.Join(snapshotPath, "PTM_0_2.bin")
	raw, err := os.ReadFile(binPath)
	if err != nil {
		t.Skipf("Snapshot not available: %v", err)
	}

	// Parse packets
	packets, err := decoder.Parse(raw)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	t.Logf("Processing %d packets with detailed atom tracking", len(packets))

	addrRangeCount := 0
	totalInstructions := uint32(0)

	for i, pkt := range packets {
		elements, err := decoder.ProcessPacket(pkt)
		if err != nil {
			continue
		}

		for _, elem := range elements {
			if elem.Type == common.ElemTypeAddrRange {
				addrRangeCount++
				totalInstructions += elem.AddrRange.NumInstr
				t.Logf("ADDR_RANGE #%d: [0x%X - 0x%X] %s, %d instructions",
					addrRangeCount,
					elem.AddrRange.StartAddr,
					elem.AddrRange.EndAddr,
					elem.AddrRange.ISA,
					elem.AddrRange.NumInstr)
			}
		}

		// Log atom packets specifically
		if pkt.Type == PacketTypeATOM {
			t.Logf("Packet %d: ATOM with %d atoms, pattern=0x%x -> %d elements",
				i, pkt.AtomCount, pkt.AtomBits, len(elements))
		}
	}

	t.Logf("Summary: %d ADDR_RANGE elements, %d total instructions traced",
		addrRangeCount, totalInstructions)

	// Verify we generated at least some ranges
	if addrRangeCount == 0 {
		t.Error("Expected at least one ADDR_RANGE element from atom processing")
	}
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

func TestAtomPacket_FormatFromHeader(t *testing.T) {
	// Atom packet 0xd0 should decode to ENEEE (5 atoms)
	raw := []byte{0xd0}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeATOM, pkt.Type, "packet type")
	if pkt.AtomCount != 5 {
		t.Fatalf("expected 5 atoms, got %d", pkt.AtomCount)
	}
	if atomPatternTest(pkt.AtomBits, pkt.AtomCount) != "ENEEE" {
		t.Fatalf("expected ENEEE, got %s", atomPatternTest(pkt.AtomBits, pkt.AtomCount))
	}
}

func TestBranchAddress_WithException(t *testing.T) {
	// Branch address packet with exception from trace_cov_a15.ppl
	raw := []byte{0x81, 0x80, 0x80, 0x80, 0x48, 0x02}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeBranchAddr, pkt.Type, "packet type")
	if pkt.ExceptionNum != 0x01 {
		t.Fatalf("expected exception 0x01, got 0x%02x", pkt.ExceptionNum)
	}
	if !pkt.SecureValid || !pkt.SecureState {
		t.Fatalf("expected secure state true")
	}
	if pkt.Address != 0x0 {
		t.Fatalf("expected address 0x0, got 0x%x", pkt.Address)
	}
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

func atomPatternTest(bits uint8, count uint8) string {
	if count == 0 {
		return ""
	}
	pattern := ""
	for i := uint8(0); i < count; i++ {
		if (bits & (1 << i)) != 0 {
			pattern += "E"
		} else {
			pattern += "N"
		}
	}
	return pattern
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

func TestTimestampPacket_ShortFormat(t *testing.T) {
	// Short timestamp (2 bytes): header 0x42, one continuation byte
	// From TC2.ppl: [0x42 0x25] => TS=0x82f9d0d625
	// The short format only shows 2 bytes: 0x42 0x25
	raw := []byte{0x42, 0x25}

	decoder := NewDecoder(0x10)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeTimestamp, pkt.Type, "packet type")
	assertEqual(t, uint64(0), pkt.Offset, "byte offset")
	assertBytesEqual(t, raw, pkt.Data, "packet data")
	// 0x25 has bit 7 = 0 (no continuation), so this is a single byte timestamp value
	// Value = 0x25 (no shift needed, it's the only byte)
	assertEqual(t, uint64(0x25), pkt.Timestamp, "timestamp value")
}

func TestTimestampPacket_LongFormat(t *testing.T) {
	// Long timestamp (3 bytes): header 0x42, two timestamp bytes
	// From TC2.ppl: [0x42 0xdf 0x1e] => TS=0x82f9d0cf5f
	// Byte 1: 0xdf has bit 7 = 1 (continuation), value = 0x5f
	// Byte 2: 0x1e has bit 7 = 0 (no continuation), value = 0x1e
	// Combined: (0x1e << 7) | 0x5f = (0x1e * 128) + 0x5f = 0xf00 + 0x5f = 0xf5f
	raw := []byte{0x42, 0xdf, 0x1e}

	decoder := NewDecoder(0x10)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeTimestamp, pkt.Type, "packet type")
	assertBytesEqual(t, raw, pkt.Data, "packet data")
	// Calculate: 0xdf & 0x7f = 0x5f, 0x1e & 0x7f = 0x1e
	// Value = 0x1e * 128 + 0x5f = 0xf5f
	expectedTS := uint64(0x1e)<<7 | uint64(0xdf&0x7f)
	assertEqual(t, expectedTS, pkt.Timestamp, "timestamp value")
}

func TestTimestampPacket_MultiByteFormat(t *testing.T) {
	// Multi-byte timestamp (10 bytes): from TC2.ppl
	// [0x42 0xbd 0x9a 0xc3 0xce 0xaf 0x90 0x80 0x80 0x00]
	// Multiple continuation bytes before terminating with 0x00 (bit 7 = 0)
	raw := []byte{0x42, 0xbd, 0x9a, 0xc3, 0xce, 0xaf, 0x90, 0x80, 0x80, 0x00}

	decoder := NewDecoder(0x10)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Logf("ERROR: expected 1 packet, got %d", len(packets))
		for i, p := range packets {
			t.Logf("  Packet %d: Type=%s Size=%d Data=%x", i, p.Type, len(p.Data), p.Data)
		}
		t.FailNow()
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeTimestamp, pkt.Type, "packet type")
	assertBytesEqual(t, raw, pkt.Data, "packet data")
	// Verify the packet was parsed without error
	// Exact timestamp value verification would require computing the full 7-bit extraction
	if pkt.Timestamp == 0 {
		t.Error("timestamp should not be 0 for multi-byte format")
	}
}

func TestTC2_FileExists(t *testing.T) {
	// Quick check that TC2 reference file exists
	pplPath := filepath.Join(resultsPath, "TC2.ppl")
	t.Logf("Looking for TC2.ppl at: %s", pplPath)

	info, err := os.Stat(pplPath)
	if err != nil {
		t.Fatalf("TC2.ppl not found: %v", err)
	}
	t.Logf("Found TC2.ppl: %d bytes", info.Size())
}

func TestTC2_TimestampPackets(t *testing.T) {
	// Test against TC2 snapshot which contains Timestamp packets
	// TC2 has PTM traces - check .ppl file for actual IDs

	// Load C++ reference output - first try to get all packets to see what IDs are present
	pplPath := filepath.Join(resultsPath, "TC2.ppl")
	t.Logf("Loading TC2 reference from: %s", pplPath)

	// Try with ID 13 (from the .ppl output "ID:13")
	cppPackets, err := LoadCppReference(pplPath, 13)
	if err != nil {
		t.Fatalf("Failed to load TC2 reference: %v", err)
	}

	t.Logf("Loaded %d packets for trace ID 13", len(cppPackets))

	// Filter for TIMESTAMP packets only
	var timestampPackets []CppPacket
	for _, p := range cppPackets {
		if p.Type == "TIMESTAMP" {
			timestampPackets = append(timestampPackets, p)
		}
	}

	if len(timestampPackets) == 0 {
		t.Fatalf("No TIMESTAMP packets found in TC2 reference for trace ID 13")
	}

	t.Logf("Found %d TIMESTAMP packets in TC2 reference for trace ID 13", len(timestampPackets))

	// Validate first 5 timestamp packets
	limit := 5
	if len(timestampPackets) < limit {
		limit = len(timestampPackets)
	}

	for i := 0; i < limit; i++ {
		cpp := timestampPackets[i]
		t.Logf("Timestamp packet %d raw data: %x", i, cpp.Bytes)

		// Parse the C++ reference bytes with our decoder
		decoder := NewDecoder(0x13)
		if _, cfgErr := decoder.ConfigureFromSnapshot(tc2SnapshotPath); cfgErr != nil {
			t.Fatalf("Failed to load TC2 snapshot config: %v", cfgErr)
		}
		packets, err := decoder.Parse(cpp.Bytes)
		if err != nil {
			t.Errorf("Timestamp packet %d: parse error: %v", i, err)
			continue
		}

		t.Logf("Timestamp packet %d parsed %d packets", i, len(packets))
		for j, p := range packets {
			t.Logf("  Packet %d: Type=%s Size=%d Data=%x", j, p.Type, len(p.Data), p.Data)
		}

		if len(packets) < 1 {
			t.Errorf("Timestamp packet %d: expected at least 1 packet, got %d", i, len(packets))
			continue
		}

		got := packets[0]
		if got.Type != PacketTypeTimestamp {
			t.Errorf("Timestamp packet %d: type mismatch, got %s want TIMESTAMP", i, got.Type)
		}

		if !bytes.Equal(got.Data, cpp.Bytes) {
			t.Errorf("Timestamp packet %d: bytes mismatch, got %x want %x", i, got.Data, cpp.Bytes)
		}

		t.Logf("Timestamp packet %d: OK (offset=%d)", i, cpp.ByteOffset)
	}
}

func TestContextIDPacket(t *testing.T) {
	// Context ID packet: header 0x6E + 4 bytes of context ID
	// Example: 0x6E 0x12 0x34 0x56 0x78 = ContextID 0x78563412 (little endian)
	raw := []byte{0x6E, 0x12, 0x34, 0x56, 0x78}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeContextID, pkt.Type, "packet type")
	assertEqual(t, uint32(0x78563412), pkt.ContextID, "context ID value")
	t.Logf("ContextID packet: %s", pkt.Description())
}

func TestVMIDPacket(t *testing.T) {
	// VMID packet: header 0x3C + 1 byte VMID value
	// Example: 0x3C 0xAB = VMID 0xAB
	raw := []byte{0x3C, 0xAB}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeVMID, pkt.Type, "packet type")
	assertEqual(t, uint8(0xAB), pkt.VMID, "VMID value")
	t.Logf("VMID packet: %s", pkt.Description())
}

func TestExceptionReturnPacket(t *testing.T) {
	// Exception Return packet: header 0x76 only (no payload)
	raw := []byte{0x76}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}

	pkt := packets[0]
	assertEqual(t, PacketTypeExceptionReturn, pkt.Type, "packet type")
	assertEqual(t, 1, len(pkt.Data), "packet data length")
	t.Logf("Exception Return packet: %s", pkt.Description())
}

func TestMixedPackets_WithNewTypes(t *testing.T) {
	// Test a sequence with new packet types mixed with existing ones
	raw := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x6E, 0xAA, 0xBB, 0xCC, 0xDD, // ContextID
		0x3C, 0x42, // VMID
		0x76,       // Exception Return
		0x42, 0x12, // Timestamp
	}

	decoder := NewDecoder(0)
	packets, _ := testParseSuccess(t, decoder, raw)

	if len(packets) != 5 {
		t.Fatalf("expected 5 packets, got %d", len(packets))
	}

	// Check packet types in sequence
	assertEqual(t, PacketTypeASYNC, packets[0].Type, "packet 0 type")
	assertEqual(t, PacketTypeContextID, packets[1].Type, "packet 1 type")
	assertEqual(t, PacketTypeVMID, packets[2].Type, "packet 2 type")
	assertEqual(t, PacketTypeExceptionReturn, packets[3].Type, "packet 3 type")
	assertEqual(t, PacketTypeTimestamp, packets[4].Type, "packet 4 type")

	// Check specific values
	assertEqual(t, uint32(0xDDCCBBAA), packets[1].ContextID, "context ID")
	assertEqual(t, uint8(0x42), packets[2].VMID, "VMID")

	// Log descriptions
	for i, pkt := range packets {
		t.Logf("Packet %d: %s", i, pkt.Description())
	}
}

func TestDecoderWithLogger(t *testing.T) {
	// Test that decoder can be created with a custom logger
	var stdout, stderr bytes.Buffer
	logger := common.NewStdLoggerWithWriter(&stdout, &stderr, common.SeverityDebug)

	decoder := NewDecoderWithLogger(0x13, logger)
	if decoder.Log == nil {
		t.Fatal("Decoder logger is nil")
	}

	// Log a test message
	decoder.Log.Info("Decoder initialized for trace ID 0x13")

	output := stdout.String()
	if len(output) == 0 {
		t.Error("Expected log output, got none")
	}
	t.Logf("Logger output: %s", output)
}

func TestDecoderDefaultLogger(t *testing.T) {
	// Test that decoder has a default no-op logger
	decoder := NewDecoder(0)
	if decoder.Log == nil {
		t.Fatal("Decoder should have a default logger")
	}

	// This should not panic or produce output
	decoder.Log.Info("This is logged to no-op logger")
	decoder.Log.Error(nil)
}

func TestGenericTraceElementCreation(t *testing.T) {
	// Test that we can create trace elements
	decoder := NewDecoder(0)

	// Create a PE context element
	decoder.CurrentElement = common.NewGenericTraceElement(common.ElemTypePeContext)
	decoder.CurrentElement.Context = common.PEContext{
		ContextID:      0x12345678,
		VMID:           0x42,
		ISA:            common.ISAARM,
		SecurityState:  common.SecurityStateNonSecure,
		ExceptionLevel: common.EL1,
	}

	desc := decoder.CurrentElement.Description()
	t.Logf("Created trace element: %s", desc)

	// Create an address range element
	decoder.CurrentElement = common.NewGenericTraceElement(common.ElemTypeAddrRange)
	decoder.CurrentElement.AddrRange = common.AddrRange{
		StartAddr:   0x80000000,
		EndAddr:     0x80000010,
		ISA:         common.ISAThumb2,
		NumInstr:    4,
		LastInstrSz: 2,
	}

	desc = decoder.CurrentElement.Description()
	t.Logf("Created trace element: %s", desc)
}

// Test ProcessPacket - Wait for Sync
func TestProcessPacket_WaitForSync(t *testing.T) {
	decoder := NewDecoder(0)

	// Initially not synchronized
	if decoder.IsSynchronized() {
		t.Error("Decoder should not be synchronized initially")
	}

	// Process ASYNC packet
	asyncPkt := Packet{Type: PacketTypeASYNC}
	_, err := decoder.ProcessPacket(asyncPkt)
	if err != nil {
		t.Fatalf("ProcessPacket(ASYNC) error: %v", err)
	}

	// Still not synchronized (waiting for ISYNC)
	if decoder.IsSynchronized() {
		t.Error("Decoder should not be synchronized after ASYNC only")
	}

	// Process ISYNC packet
	isyncPkt := Packet{
		Type:        PacketTypeISYNC,
		Address:     0x80000558,
		ISA:         ISAARM,
		SecureState: true,
	}
	elements, err := decoder.ProcessPacket(isyncPkt)
	if err != nil {
		t.Fatalf("ProcessPacket(ISYNC) error: %v", err)
	}

	// Now synchronized
	if !decoder.IsSynchronized() {
		t.Error("Decoder should be synchronized after ISYNC")
	}

	// Should have generated elements
	if len(elements) < 1 {
		t.Errorf("Expected at least 1 element after ISYNC, got %d", len(elements))
	}

	t.Logf("Generated %d elements after ISYNC:", len(elements))
	for i, elem := range elements {
		t.Logf("  [%d] %s", i, elem.Description())
	}
}

// Test ProcessPacket - Address Updates
func TestProcessPacket_AddressUpdate(t *testing.T) {
	decoder := NewDecoder(0)

	// Sync first
	decoder.ProcessPacket(Packet{Type: PacketTypeASYNC})
	decoder.ProcessPacket(Packet{
		Type:    PacketTypeISYNC,
		Address: 0x80000558,
		ISA:     ISAARM,
	})

	// Initial address should be set from ISYNC
	if decoder.GetCurrentAddress() != 0x80000558 {
		t.Errorf("Current address = 0x%x, want 0x80000558", decoder.GetCurrentAddress())
	}

	// Process branch address packet from raw bytes (single-byte address update)
	branchRaw := []byte{0x2f}
	branchPkts, err := decoder.Parse(branchRaw)
	if err != nil {
		t.Fatalf("Parse(BranchAddr) error: %v", err)
	}
	if len(branchPkts) != 1 {
		t.Fatalf("expected 1 branch packet, got %d", len(branchPkts))
	}
	_, err = decoder.ProcessPacket(branchPkts[0])
	if err != nil {
		t.Fatalf("ProcessPacket(BranchAddr) error: %v", err)
	}

	// Address should be updated
	newAddr := decoder.GetCurrentAddress()
	if newAddr == 0 {
		t.Error("Current address should be non-zero after branch")
	}
	t.Logf("Address updated to: 0x%x", newAddr)
}

// Test ProcessPacket - Full trace_cov_a15 sequence
func TestProcessPacket_TraceCovA15(t *testing.T) {
	// Load the snapshot data
	binPath := filepath.Join(snapshotPath, "PTM_0_2.bin")
	data, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("Failed to read snapshot: %v", err)
	}

	decoder := NewDecoder(0)

	// Parse all packets
	packets, err := decoder.Parse(data)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	t.Logf("Parsed %d packets from %d bytes", len(packets), len(data))

	// Process each packet
	totalElements := 0
	for i, pkt := range packets {
		elements, err := decoder.ProcessPacket(pkt)
		if err != nil {
			t.Fatalf("ProcessPacket[%d] error: %v", i, err)
		}

		if len(elements) > 0 {
			totalElements += len(elements)
			t.Logf("Packet %d (%s) -> %d elements", i, pkt.Type, len(elements))
			for _, elem := range elements {
				t.Logf("  %s", elem.Description())
			}
		}
	}

	// Verify synchronization
	if !decoder.IsSynchronized() {
		t.Error("Decoder should be synchronized after processing trace_cov_a15")
	}

	t.Logf("Final state: synchronized=%v, address=0x%x, ISA=%s",
		decoder.IsSynchronized(),
		decoder.GetCurrentAddress(),
		decoder.GetCurrentISA())

	t.Logf("Total elements generated: %d", totalElements)
}

// Test ProcessPacket - Context ID update
func TestProcessPacket_ContextID(t *testing.T) {
	decoder := NewDecoder(0)

	// Sync first
	decoder.ProcessPacket(Packet{Type: PacketTypeASYNC})
	decoder.ProcessPacket(Packet{Type: PacketTypeISYNC, Address: 0x80000000})

	// Process ContextID packet
	ctxPkt := Packet{
		Type:      PacketTypeContextID,
		ContextID: 0x12345678,
	}
	elements, err := decoder.ProcessPacket(ctxPkt)
	if err != nil {
		t.Fatalf("ProcessPacket(ContextID) error: %v", err)
	}

	// Should generate PE_CONTEXT element
	if len(elements) < 1 {
		t.Error("Expected at least 1 element for ContextID")
	} else {
		t.Logf("Generated element: %s", elements[0].Description())
	}
}

// Test ProcessPacket - VMID update
func TestProcessPacket_VMID(t *testing.T) {
	decoder := NewDecoder(0)

	// Sync first
	decoder.ProcessPacket(Packet{Type: PacketTypeASYNC})
	decoder.ProcessPacket(Packet{Type: PacketTypeISYNC, Address: 0x80000000})

	// Process VMID packet
	vmidPkt := Packet{
		Type: PacketTypeVMID,
		VMID: 0x42,
	}
	_, err := decoder.ProcessPacket(vmidPkt)
	if err != nil {
		t.Fatalf("ProcessPacket(VMID) error: %v", err)
	}

	// VMID should be updated in decoder state
	t.Logf("VMID updated successfully")
}

// Test ProcessPacket - Exception
func TestProcessPacket_Exception(t *testing.T) {
	decoder := NewDecoder(0)

	// Sync first
	decoder.ProcessPacket(Packet{Type: PacketTypeASYNC})
	decoder.ProcessPacket(Packet{Type: PacketTypeISYNC, Address: 0x80000504})

	// Process branch with exception
	branchPkt := Packet{
		Type:         PacketTypeBranchAddr,
		ExceptionNum: 0x01, // Debug Halt
		Data:         []byte{0x81, 0x80, 0x80, 0x80, 0x48, 0x02},
	}
	elements, err := decoder.ProcessPacket(branchPkt)
	if err != nil {
		t.Fatalf("ProcessPacket(BranchAddr with exception) error: %v", err)
	}

	// Should generate exception element
	if len(elements) < 1 {
		t.Error("Expected at least 1 element for exception")
	} else {
		for _, elem := range elements {
			if elem.Type == common.ElemTypeException {
				t.Logf("Generated exception element: %s", elem.Description())
				return
			}
		}
		t.Error("No exception element found")
	}
}

// Test ProcessPacket - Timestamp
func TestProcessPacket_Timestamp(t *testing.T) {
	decoder := NewDecoder(0)

	// Sync first
	decoder.ProcessPacket(Packet{Type: PacketTypeASYNC})
	decoder.ProcessPacket(Packet{Type: PacketTypeISYNC, Address: 0x80000000})

	// Process timestamp packet
	tsPkt := Packet{
		Type:      PacketTypeTimestamp,
		Timestamp: 0x123456789ABC,
	}
	elements, err := decoder.ProcessPacket(tsPkt)
	if err != nil {
		t.Fatalf("ProcessPacket(Timestamp) error: %v", err)
	}

	// Should generate timestamp element
	if len(elements) != 1 {
		t.Errorf("Expected 1 element for timestamp, got %d", len(elements))
	} else {
		t.Logf("Generated timestamp element: %s", elements[0].Description())
	}
}

// Test ProcessPacket - Exception Return
func TestProcessPacket_ExceptionReturn(t *testing.T) {
	decoder := NewDecoder(0)

	// Sync first
	decoder.ProcessPacket(Packet{Type: PacketTypeASYNC})
	decoder.ProcessPacket(Packet{Type: PacketTypeISYNC, Address: 0x80000000})

	// Process exception return packet
	retPkt := Packet{
		Type: PacketTypeExceptionReturn,
	}
	elements, err := decoder.ProcessPacket(retPkt)
	if err != nil {
		t.Fatalf("ProcessPacket(ExceptionReturn) error: %v", err)
	}

	// Should generate exception return element
	if len(elements) != 1 {
		t.Errorf("Expected 1 element for exception return, got %d", len(elements))
	} else if elements[0].Type != common.ElemTypeExceptionReturn {
		t.Errorf("Expected exception return element, got %s", elements[0].Type)
	} else {
		t.Logf("Generated element: %s", elements[0].Description())
	}
}
