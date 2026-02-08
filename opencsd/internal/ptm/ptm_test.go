package ptm

import (
	"bufio"
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
	for i := range logLines {
		if logLines[i] != goOutput[i] {
			t.Errorf("Mismatch at line %d: expected %q, got %q", i, logLines[i], goOutput[i])
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
