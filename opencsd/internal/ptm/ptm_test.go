package ptm

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
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
