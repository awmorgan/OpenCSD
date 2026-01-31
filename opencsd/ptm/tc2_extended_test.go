package ptm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opencsd/common"
	"opencsd/frame"
	"opencsd/printer"
	"opencsd/ptm"
	"opencsd/tests/helpers"
)

func TestTC2FullDecodeExtended(t *testing.T) {
	snapshotPath := "../../decoder/tests/snapshots/TC2"
	pplPath := "../../decoder/tests/results/TC2.ppl"

	// Load expected records
	expectedRecords, err := helpers.LoadPPLRecords(pplPath)
	if err != nil {
		t.Fatalf("Failed to load PPL file: %v", err)
	}

	// Filter to just PTM trace ID 0x13 elements
	var expectedLines []string
	for _, rec := range expectedRecords {
		if strings.ToLower(rec.ID) == "13" && rec.Kind == helpers.PPLRecordElement {
			expectedLines = append(expectedLines, rec.Line)
		}
	}
	t.Logf("Expected %d element lines for trace ID 0x13", len(expectedLines))

	// Load trace data
	tracePath := filepath.Join(snapshotPath, "cstrace.bin")
	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("Failed to read trace data: %v", err)
	}

	// Demux trace data
	demux := frame.NewDemuxer()
	demux.MemAligned = true
	demux.ResetOn4Sync = true
	idData := demux.Process(traceData)

	ptmData, ok := idData[0x13]
	if !ok {
		t.Fatal("No PTM data for ID 0x13")
	}

	// Find ASYNC packet
	asyncPattern := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
	asyncOffset := -1
	for i := 0; i+6 <= len(ptmData); i++ {
		match := true
		for j := 0; j < 6; j++ {
			if ptmData[i+j] != asyncPattern[j] {
				match = false
				break
			}
		}
		if match {
			asyncOffset = i
			break
		}
	}
	if asyncOffset < 0 {
		t.Fatal("ASYNC packet not found in PTM data")
	}
	ptmData = ptmData[asyncOffset:]

	// Load memory
	memMap := common.NewMultiRegionMemory()
	kernelPath := filepath.Join(snapshotPath, "kernel_dump.bin")
	kernelData, err := os.ReadFile(kernelPath)
	if err != nil {
		t.Fatalf("Failed to read kernel dump: %v", err)
	}
	memMap.AddRegion(common.NewMemoryBuffer(0xC0008000, kernelData))

	// Create decoder
	decoder := ptm.NewDecoder(0x13)
	decoder.SetMemoryAccessor(memMap)
	decoder.CycleAccEnable = true
	decoder.RetStackEnable = false

	// Parse packets
	packets, err := decoder.Parse(ptmData)
	if err != nil {
		t.Fatalf("Failed to parse PTM packets: %v", err)
	}

	// Decode packets to elements
	decoder.Reset()
	var actualLines []string
	for _, pkt := range packets {
		elems, err := decoder.ProcessPacket(pkt)
		if err != nil {
			continue
		}
		for _, elem := range elems {
			line := printer.FormatGenericElementLine(pkt.Offset, 0x13, elem)
			actualLines = append(actualLines, line)
		}
	}
	t.Logf("Generated %d element lines (expected %d)", len(actualLines), len(expectedLines))

	// Compare all lines and find first mismatch
	maxCompare := len(actualLines)
	if len(expectedLines) < maxCompare {
		maxCompare = len(expectedLines)
	}

	firstMismatch := -1
	matches := 0
	for i := 0; i < maxCompare; i++ {
		actualNoIdx := stripIdx(actualLines[i])
		expectedNoIdx := stripIdx(expectedLines[i])

		if actualNoIdx == expectedNoIdx {
			matches++
		} else {
			if firstMismatch < 0 {
				firstMismatch = i
			}
		}
	}

	t.Logf("Matched %d/%d lines", matches, maxCompare)

	if firstMismatch >= 0 {
		t.Logf("First mismatch at line %d:", firstMismatch)
		// Show context around mismatch
		startCtx := firstMismatch - 3
		if startCtx < 0 {
			startCtx = 0
		}
		endCtx := firstMismatch + 3
		if endCtx > maxCompare {
			endCtx = maxCompare
		}

		t.Log("--- Context ---")
		for i := startCtx; i < endCtx; i++ {
			actual := ""
			expected := ""
			if i < len(actualLines) {
				actual = stripIdx(actualLines[i])
			}
			if i < len(expectedLines) {
				expected = stripIdx(expectedLines[i])
			}
			marker := "  "
			if i == firstMismatch {
				marker = ">>"
			}
			if actual == expected {
				t.Logf("%s Line %d: ✓ matches", marker, i)
			} else {
				t.Logf("%s Line %d: MISMATCH", marker, i)
				t.Logf("     Exp: %s", expected)
				t.Logf("     Act: %s", actual)
			}
		}
	}

	// Check for extra or missing lines at end
	if len(actualLines) != len(expectedLines) {
		t.Logf("Count difference: expected %d, actual %d (%d difference)",
			len(expectedLines), len(actualLines), len(expectedLines)-len(actualLines))
	}
}

// stripIdx removes the "Idx:NNNN; " prefix from a line for comparison
func stripIdx2(line string) string {
	if idx := strings.Index(line, "; ID:"); idx > 0 {
		return line[idx+2:]
	}
	return line
}
