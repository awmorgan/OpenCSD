package ptm

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/memacc"
)

func TestPtmParity(t *testing.T) {
	cppLog := "testdata/ptm-pkts-only.ppl"
	binFile := "testdata/PTM_0_2.bin"

	data, err := os.ReadFile(binFile)
	if err != nil {
		t.Fatalf("Failed to read trace bin: %v", err)
	}

	goOutput, err := ParsePtmPackets(data)
	if err != nil {
		t.Fatalf("ParsePtmPackets failed: %v", err)
	}
	logLines := loadLogLines(t, cppLog)
	if len(logLines) != len(goOutput) {
		t.Fatalf("Mismatched number of lines: expected %d, got %d", len(logLines), len(goOutput))
	}
	for i, pkt := range goOutput {
		line := fmt.Sprintf("Idx:%d; ID:0; [%s];\t%s", pkt.Index, formatRawBytes(pkt.RawBytes), pkt.ToString())
		if logLines[i] != line {
			t.Errorf("Mismatch at line %d:\nexpected %q\ngot      %q", i, logLines[i], line)
		}
	}

}

func loadLogLines(t *testing.T, path string) []string {
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Idx:") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	return lines
}

func formatRawBytes(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		// Matches C++ format: lowercase hex, space after every byte (including last)
		// e.g., "0x01 0x02 " -> "[0x01 0x02 ]"
		fmt.Fprintf(&sb, "0x%02x ", b)
	}
	return sb.String()
}

type elemRecord struct {
	index    int64
	elemType common.GenTrcElemType
}

type elemSink struct {
	elems []elemRecord
}

func (s *elemSink) TraceElemIn(index int64, chanID uint8, elem *common.TraceElement) common.DataPathResp {
	s.elems = append(s.elems, elemRecord{index: index, elemType: elem.ElemType})
	return common.RespCont
}

func decodeElems(t *testing.T, data []byte) []elemRecord {
	t.Helper()
	sink := &elemSink{}
	decoder := NewPtmDecoder(sink, memacc.NewMapper())
	resp, _, err := decoder.TraceDataIn(common.OpData, 0, data)
	if err != nil {
		t.Fatalf("TraceDataIn failed: %v", err)
	}
	if !resp.IsCont() {
		t.Fatalf("TraceDataIn returned non-continue response: %v", resp)
	}
	return sink.elems
}

func assertElemSeq(t *testing.T, got []elemRecord, want []elemRecord) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Expected %d elements, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i].elemType != want[i].elemType || got[i].index != want[i].index {
			t.Fatalf("Element %d mismatch: got (%v @ %d), want (%v @ %d)", i, got[i].elemType, got[i].index, want[i].elemType, want[i].index)
		}
	}
}

func TestPtmDecoderReservedRecoveryGate(t *testing.T) {
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // ISYNC
		0x02,       // RESERVED
		0x42, 0x00, // TIMESTAMP (would emit if synced)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // ISYNC
	}

	got := decodeElems(t, data)
	want := []elemRecord{
		{index: 0, elemType: common.ElemNoSync},
		{index: 6, elemType: common.ElemPeContext},
		{index: 6, elemType: common.ElemTraceOn},
		{index: 12, elemType: common.ElemNoSync},
		{index: 21, elemType: common.ElemPeContext},
		{index: 21, elemType: common.ElemTraceOn},
	}
	assertElemSeq(t, got, want)
}

func TestPtmDecoderBadSequenceRecoveryGate(t *testing.T) {
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // ISYNC
		0x00, 0x01, // BAD_SEQUENCE from malformed ASYNC
		0x42, 0x00, // TIMESTAMP (would emit if synced)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // ISYNC
	}

	got := decodeElems(t, data)
	want := []elemRecord{
		{index: 0, elemType: common.ElemNoSync},
		{index: 6, elemType: common.ElemPeContext},
		{index: 6, elemType: common.ElemTraceOn},
		{index: 12, elemType: common.ElemNoSync},
		{index: 22, elemType: common.ElemPeContext},
		{index: 22, elemType: common.ElemTraceOn},
	}
	assertElemSeq(t, got, want)
}

func TestPtmSimpleTrigger(t *testing.T) {
	// Simple ASYNC + ISYNC + TRIGGER to verify TRIGGER works
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // ISYNC
		0x0C, // TRIGGER
	}

	pkts, err := ParsePtmPackets(data)
	if err != nil {
		t.Fatalf("ParsePtmPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	if pkts[2].typeID != ptmPktTrigger {
		t.Errorf("Expected third packet to be TRIGGER, got %v", pkts[2].typeID)
	}
}

func TestPtmLongZeroRunAsync(t *testing.T) {
	// 20 zeros + 0x80 should trigger ASYNC_PAD_0_LIMIT discard
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 10 zeros
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 20 zeros total
		0x80,                               // ASYNC terminator
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // ISYNC
		0x0C, // TRIGGER
	}

	pkts, err := ParsePtmPackets(data)
	if err != nil {
		t.Fatalf("ParsePtmPackets failed: %v", err)
	}

	// Verify packet indices and lengths
	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	// ASYNC: after discarding first 11 zeros, starts at index 11
	// Contains 9 remaining zeros + 0x80 = length 10
	if pkts[0].typeID != ptmPktAsync {
		t.Fatalf("Expected first packet to be ASYNC, got %v", pkts[0].typeID)
	}
	if pkts[0].Index != 11 {
		t.Errorf("ASYNC Index: expected 11, got %d", pkts[0].Index)
	}
	if len(pkts[0].RawBytes) != 10 {
		t.Errorf("ASYNC length: expected 10, got %d", len(pkts[0].RawBytes))
	}

	// ISYNC: starts at 21 (11 + 10), length 6
	if pkts[1].typeID != ptmPktISync {
		t.Fatalf("Expected second packet to be ISYNC, got %v", pkts[1].typeID)
	}
	if pkts[1].Index != 21 {
		t.Errorf("ISYNC Index: expected 21, got %d", pkts[1].Index)
	}
	if len(pkts[1].RawBytes) != 6 {
		t.Errorf("ISYNC length: expected 6, got %d", len(pkts[1].RawBytes))
	}

	// TRIGGER: starts at 27 (21 + 6), length 1
	if pkts[2].typeID != ptmPktTrigger {
		t.Fatalf("Expected third packet to be TRIGGER, got %v", pkts[2].typeID)
	}
	if pkts[2].Index != 27 {
		t.Errorf("TRIGGER Index: expected 27, got %d", pkts[2].Index)
	}
	if len(pkts[2].RawBytes) != 1 {
		t.Errorf("TRIGGER length: expected 1, got %d", len(pkts[2].RawBytes))
	}
}

// TestPtmISyncWithCycleCount verifies ISYNC parsing with cycle count (cycleAcc=true, reason!=0)
func TestPtmISyncWithCycleCount(t *testing.T) {
	// Construct processor with cycleAcc enabled
	proc := NewPktProcessor()
	proc.cycleAcc = true // Enable cycle accurate mode

	// ASYNC + ISYNC with reason=1 (Trace Enable) and cycle count
	// ISYNC: 0x08 (hdr) + 4 addr bytes + info byte (reason=1) + cycle count bytes
	// Info byte: reason=1 (bits 5-6), NS=0, AltISA=0, Hyp=0
	// reason bits: 0x20 (001 << 5)
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC @ 0
		0x08,       // ISYNC header @ 6
		0x00,       // addr[7:1] (bit 0 = ISA)
		0x00, 0x00, // addr[15:8], addr[23:16]
		0x00, // addr[31:24]
		0x20, // info byte: reason=1, NS=0, AltISA=0, Hyp=0
		0x05, // cycle count: single byte, no continuation (bit 6 = 0), value = 1
		0x0C, // TRIGGER @ 13
	}

	proc.AddData(data, 0)
	pkts, err := proc.ProcessPackets()
	if err != nil {
		t.Fatalf("ProcessPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	// ISYNC with cycle count should be 7 bytes (6 base + 1 cycle count)
	if pkts[1].typeID != ptmPktISync {
		t.Fatalf("Expected ISYNC packet, got %v", pkts[1].typeID)
	}
	if pkts[1].Index != 6 {
		t.Errorf("ISYNC Index: expected 6, got %d", pkts[1].Index)
	}
	if len(pkts[1].RawBytes) != 7 {
		t.Errorf("ISYNC length: expected 7 (6 base + 1 CC), got %d", len(pkts[1].RawBytes))
	}
	if !pkts[1].ccValid {
		t.Errorf("ISYNC should have valid cycle count")
	}
	if pkts[1].cycleCount != 1 {
		t.Errorf("ISYNC cycle count: expected 1, got %d", pkts[1].cycleCount)
	}

	// TRIGGER should start at index 13 (6 + 7)
	if pkts[2].Index != 13 {
		t.Errorf("TRIGGER Index: expected 13, got %d", pkts[2].Index)
	}
}

// TestPtmISyncWithContextID verifies ISYNC parsing with context ID
func TestPtmISyncWithContextID(t *testing.T) {
	// Construct processor with ctxtIDBytes=4
	proc := NewPktProcessor()
	proc.ctxtIDBytes = 4 // 4 bytes of context ID

	// ASYNC + ISYNC with context ID (reason=0, no cycle count)
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC @ 0
		0x08,       // ISYNC header @ 6
		0x00,       // addr[7:1] (bit 0 = ISA)
		0x00, 0x00, // addr[15:8], addr[23:16]
		0x00,                   // addr[31:24]
		0x00,                   // info byte: reason=0, NS=0, AltISA=0, Hyp=0
		0x12, 0x34, 0x56, 0x78, // context ID (4 bytes)
		0x0C, // TRIGGER @ 16
	}

	proc.AddData(data, 0)
	pkts, err := proc.ProcessPackets()
	if err != nil {
		t.Fatalf("ProcessPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	// ISYNC with context ID should be 10 bytes (6 base + 4 context ID)
	if pkts[1].typeID != ptmPktISync {
		t.Fatalf("Expected ISYNC packet, got %v", pkts[1].typeID)
	}
	if pkts[1].Index != 6 {
		t.Errorf("ISYNC Index: expected 6, got %d", pkts[1].Index)
	}
	if len(pkts[1].RawBytes) != 10 {
		t.Errorf("ISYNC length: expected 10 (6 base + 4 ctxtID), got %d", len(pkts[1].RawBytes))
	}
	if !pkts[1].context.updatedC {
		t.Errorf("ISYNC should have updated context ID")
	}
	expectedCtxtID := uint32(0x78563412) // Little endian
	if pkts[1].context.ctxtID != expectedCtxtID {
		t.Errorf("ISYNC context ID: expected 0x%08X, got 0x%08X", expectedCtxtID, pkts[1].context.ctxtID)
	}

	// TRIGGER should start at index 16 (6 + 10)
	if pkts[2].Index != 16 {
		t.Errorf("TRIGGER Index: expected 16, got %d", pkts[2].Index)
	}
}

// TestPtmISyncMultiByteCycleCount verifies multi-byte cycle count handling
func TestPtmISyncMultiByteCycleCount(t *testing.T) {
	proc := NewPktProcessor()
	proc.cycleAcc = true

	// ISYNC with 3-byte cycle count
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC @ 0
		0x08,       // ISYNC header @ 6
		0x00,       // addr[7:1]
		0x00, 0x00, // addr bytes
		0x00, // addr byte
		0x20, // info byte: reason=1
		0x45, // CC byte 0: bit 6=1 (continue), bits[5:2]=0001, value bits=0001
		0x82, // CC byte 1: bit 7=1 (continue), bits[6:0]=0x02
		0x03, // CC byte 2: bit 7=0 (stop), bits[6:0]=0x03
		0x0C, // TRIGGER @ 15
	}

	proc.AddData(data, 0)
	pkts, err := proc.ProcessPackets()
	if err != nil {
		t.Fatalf("ProcessPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	// ISYNC with 3-byte cycle count should be 9 bytes (6 base + 3 CC)
	if len(pkts[1].RawBytes) != 9 {
		t.Errorf("ISYNC length: expected 9 (6 base + 3 CC), got %d", len(pkts[1].RawBytes))
	}

	// TRIGGER should start at index 15 (6 + 9)
	if pkts[2].Index != 15 {
		t.Errorf("TRIGGER Index: expected 15, got %d", pkts[2].Index)
	}
}

func TestPtmTimestamp32OneByteNoCycleCount(t *testing.T) {
	proc := NewPktProcessor()
	proc.cycleAcc = false
	proc.tsPkt64 = false

	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC @ 0
		0x42, // TIMESTAMP header (32-bit) @ 6
		0x01, // TS payload: 1 byte, stop bit clear
		0x0C, // TRIGGER @ 8
	}

	proc.AddData(data, 0)
	pkts, err := proc.ProcessPackets()
	if err != nil {
		t.Fatalf("ProcessPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	if pkts[1].typeID != ptmPktTimestamp {
		t.Fatalf("Expected TIMESTAMP packet, got %v", pkts[1].typeID)
	}
	if pkts[1].Index != 6 {
		t.Errorf("TIMESTAMP Index: expected 6, got %d", pkts[1].Index)
	}
	if len(pkts[1].RawBytes) != 2 {
		t.Errorf("TIMESTAMP length: expected 2 (hdr + 1), got %d", len(pkts[1].RawBytes))
	}
	if pkts[2].Index != 8 {
		t.Errorf("TRIGGER Index: expected 8, got %d", pkts[2].Index)
	}
}

func TestPtmTimestamp64WithCycleCount(t *testing.T) {
	proc := NewPktProcessor()
	proc.cycleAcc = true
	proc.tsPkt64 = true

	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC @ 0
		0x46, // TIMESTAMP header (64-bit) @ 6
		0x81, // TS payload: cont
		0x80, // TS payload: cont
		0x01, // TS payload: stop
		0x45, // CC byte 0: cont (bit6)
		0x82, // CC byte 1: cont (bit7)
		0x03, // CC byte 2: stop (bit7=0)
		0x0C, // TRIGGER @ 13
	}

	proc.AddData(data, 0)
	pkts, err := proc.ProcessPackets()
	if err != nil {
		t.Fatalf("ProcessPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	if pkts[1].typeID != ptmPktTimestamp {
		t.Fatalf("Expected TIMESTAMP packet, got %v", pkts[1].typeID)
	}
	if pkts[1].Index != 6 {
		t.Errorf("TIMESTAMP Index: expected 6, got %d", pkts[1].Index)
	}
	if len(pkts[1].RawBytes) != 7 {
		t.Errorf("TIMESTAMP length: expected 7 (hdr + 3 TS + 3 CC), got %d", len(pkts[1].RawBytes))
	}
	if !pkts[1].ccValid {
		t.Errorf("TIMESTAMP should have valid cycle count")
	}
	if pkts[2].Index != 13 {
		t.Errorf("TRIGGER Index: expected 13, got %d", pkts[2].Index)
	}
}

func TestPtmBranchAddrSingleByteNoCycleCount(t *testing.T) {
	proc := NewPktProcessor()
	proc.cycleAcc = false

	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC @ 0
		0x01, // BRANCH ADDR: 1-byte addr, no exception
		0x0C, // TRIGGER @ 7
	}

	proc.AddData(data, 0)
	pkts, err := proc.ProcessPackets()
	if err != nil {
		t.Fatalf("ProcessPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	if pkts[1].typeID != ptmPktBranchAddress {
		t.Fatalf("Expected BRANCH ADDRESS packet, got %v", pkts[1].typeID)
	}
	if pkts[1].Index != 6 {
		t.Errorf("BRANCH Index: expected 6, got %d", pkts[1].Index)
	}
	if len(pkts[1].RawBytes) != 1 {
		t.Errorf("BRANCH length: expected 1, got %d", len(pkts[1].RawBytes))
	}
	if pkts[2].Index != 7 {
		t.Errorf("TRIGGER Index: expected 7, got %d", pkts[2].Index)
	}
}

func TestPtmBranchAddrMultiByteExcepCycleCount(t *testing.T) {
	proc := NewPktProcessor()
	proc.cycleAcc = true

	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // ASYNC @ 0
		0x81, // BRANCH ADDR byte 0: cont
		0x80, // BRANCH ADDR byte 1: cont
		0x41, // BRANCH ADDR byte 2: stop, exception present (bit6)
		0x80, // EXC byte 0: cont (bit7)
		0x01, // EXC byte 1: stop
		0x44, // CC byte 0: cont (bit6)
		0x81, // CC byte 1: cont (bit7)
		0x02, // CC byte 2: stop
		0x0C, // TRIGGER @ 14
	}

	proc.AddData(data, 0)
	pkts, err := proc.ProcessPackets()
	if err != nil {
		t.Fatalf("ProcessPackets failed: %v", err)
	}

	if len(pkts) != 3 {
		t.Fatalf("Expected 3 packets, got %d", len(pkts))
	}

	if pkts[1].typeID != ptmPktBranchAddress {
		t.Fatalf("Expected BRANCH ADDRESS packet, got %v", pkts[1].typeID)
	}
	if pkts[1].Index != 6 {
		t.Errorf("BRANCH Index: expected 6, got %d", pkts[1].Index)
	}
	if len(pkts[1].RawBytes) != 8 {
		t.Errorf("BRANCH length: expected 8 (3 addr + 2 exc + 3 cc), got %d", len(pkts[1].RawBytes))
	}
	if !pkts[1].ccValid {
		t.Errorf("BRANCH should have valid cycle count")
	}
	if pkts[2].Index != 14 {
		t.Errorf("TRIGGER Index: expected 14, got %d", pkts[2].Index)
	}
}
