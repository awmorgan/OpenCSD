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
