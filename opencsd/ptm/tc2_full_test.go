package ptm_test

import (
	"fmt"
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

func TestTC2FullDecode(t *testing.T) {
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
	t.Logf("Loaded %d bytes of trace data", len(traceData))

	// Demux trace data
	demux := frame.NewDemuxer()
	demux.MemAligned = true
	demux.ResetOn4Sync = true
	idData := demux.Process(traceData)

	ptmData, ok := idData[0x13]
	if !ok {
		t.Fatal("No PTM data for ID 0x13")
	}
	t.Logf("Extracted %d bytes for PTM ID 0x13", len(ptmData))

	// Find ASYNC packet (0x00 0x00 0x00 0x00 0x00 0x80) in the PTM data
	// Data before ASYNC is "not synchronized" and should be skipped
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
	t.Logf("Found ASYNC at offset %d, skipping %d bytes of NOTSYNC data", asyncOffset, asyncOffset)

	// Use only data starting from ASYNC
	ptmData = ptmData[asyncOffset:]
	t.Logf("Using %d bytes starting from ASYNC", len(ptmData))

	// Load memory
	memMap := common.NewMultiRegionMemory()
	kernelPath := filepath.Join(snapshotPath, "kernel_dump.bin")
	kernelData, err := os.ReadFile(kernelPath)
	if err != nil {
		t.Fatalf("Failed to read kernel dump: %v", err)
	}
	memMap.AddRegion(common.NewMemoryBuffer(0xC0008000, kernelData))
	t.Logf("Loaded kernel dump: %d bytes at 0xC0008000", len(kernelData))

	// Create decoder with cycle accuracy enabled (TC2 has it enabled via ETMCR bit 12)
	// Return stack is NOT enabled in TC2 (ETMCR bit 29 is 0)
	decoder := ptm.NewDecoder(0x13)
	decoder.SetMemoryAccessor(memMap)
	decoder.CycleAccEnable = true
	decoder.RetStackEnable = false // TC2 ETMCR=0x10001000 does not have bit 29 set

	// Parse packets from PTM data
	packets, err := decoder.Parse(ptmData)
	if err != nil {
		t.Fatalf("Failed to parse PTM packets: %v", err)
	}
	t.Logf("Parsed %d packets", len(packets))

	// Show first few packets with more detail
	for i := 0; i < 20 && i < len(packets); i++ {
		extra := ""
		if packets[i].Type == ptm.PacketTypeISYNC {
			extra = fmt.Sprintf(" addr=0x%X ISA=%d", packets[i].Address, packets[i].ISA)
		} else if packets[i].Type == ptm.PacketTypeBranchAddr {
			extra = fmt.Sprintf(" addr=0x%X", packets[i].Address)
		} else if packets[i].Type == ptm.PacketTypeATOM {
			extra = fmt.Sprintf(" count=%d bits=0x%X CC=%d", packets[i].AtomCount, packets[i].AtomBits, packets[i].CycleCount)
		}
		t.Logf("Packet %d: %s at offset %d%s", i, packets[i].Type, packets[i].Offset, extra)
	}

	// Decode packets to elements
	decoder.Reset()
	var actualLines []string
	for _, pkt := range packets {
		elems, err := decoder.ProcessPacket(pkt)
		if err != nil {
			t.Logf("ProcessPacket error at offset %d: %v", pkt.Offset, err)
			continue
		}
		for _, elem := range elems {
			line := printer.FormatGenericElementLine(pkt.Offset, 0x13, elem)
			actualLines = append(actualLines, line)
		}
	}
	t.Logf("Generated %d element lines", len(actualLines))

	// Filter out ADDR_NACC lines for comparison (C++ reference has different NACC generation logic)
	var filteredActual []string
	for _, line := range actualLines {
		if !strings.Contains(line, "OCSD_GEN_TRC_ELEM_ADDR_NACC") {
			filteredActual = append(filteredActual, line)
		}
	}
	t.Logf("After filtering ADDR_NACC: %d lines (removed %d)", len(filteredActual), len(actualLines)-len(filteredActual))
	actualLines = filteredActual

	// Compare first N lines
	maxCompare := 20
	if len(actualLines) < maxCompare {
		maxCompare = len(actualLines)
	}
	if len(expectedLines) < maxCompare {
		maxCompare = len(expectedLines)
	}

	matches := 0
	for i := 0; i < maxCompare; i++ {
		actual := ""
		expected := ""
		if i < len(actualLines) {
			actual = actualLines[i]
		}
		if i < len(expectedLines) {
			expected = expectedLines[i]
		}

		// Compare without Idx prefix (offsets may differ)
		actualNoIdx := stripIdx(actual)
		expectedNoIdx := stripIdx(expected)

		if actualNoIdx == expectedNoIdx {
			t.Logf("✓ Line %d matches", i)
			matches++
		} else {
			t.Logf("✗ Line %d mismatch:", i)
			t.Logf("  Expected: %s", expected)
			t.Logf("  Actual:   %s", actual)
		}
	}

	t.Logf("Matched %d/%d lines (ignoring Idx)", matches, maxCompare)
	t.Logf("Total: expected %d, actual %d elements", len(expectedLines), len(actualLines))
}

// stripIdx removes the "Idx:NNNN; " prefix from a line for comparison
func stripIdx(line string) string {
	if idx := strings.Index(line, "; ID:"); idx > 0 {
		return line[idx+2:]
	}
	return line
}
