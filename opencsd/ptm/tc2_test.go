package ptm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opencsd/common"
	"opencsd/printer"
	"opencsd/ptm"
	"opencsd/tests/helpers"
)

func TestTC2Compare(t *testing.T) {
	snapshotPath := "../../decoder/tests/snapshots/TC2"
	pplPath := "../../decoder/tests/results/TC2.ppl"

	// TC2 uses PTM trace ID 0x13 (from device_8.ini)
	// The trace data is in cstrace.bin which is muxed with multiple trace sources
	// For now, we need to extract just PTM ID 0x13 packets

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

	t.Logf("Found %d expected element lines for trace ID 0x13", len(expectedLines))
	if len(expectedLines) == 0 {
		t.Fatal("No expected lines found")
	}

	// Show first few expected lines for debugging
	for i := 0; i < 10 && i < len(expectedLines); i++ {
		t.Logf("Expected[%d]: %s", i, expectedLines[i])
	}

	// Load memory - TC2 has kernel_dump.bin at 0xC0008000
	memMap := common.NewMultiRegionMemory()
	kernelPath := filepath.Join(snapshotPath, "kernel_dump.bin")
	kernelData, err := os.ReadFile(kernelPath)
	if err != nil {
		t.Fatalf("Failed to read kernel dump: %v", err)
	}
	memMap.AddRegion(common.NewMemoryBuffer(0xC0008000, kernelData))
	t.Logf("Loaded kernel dump: %d bytes at 0xC0008000", len(kernelData))

	// TC2 uses a muxed trace stream (cstrace.bin)
	// We need to demux it to extract just the PTM ID 0x13 packets
	// For now, let's just verify the memory access and ADDR_NACC handling works
	// by manually simulating what would happen

	// Look at first ADDR_NACC in expected output
	for i, line := range expectedLines {
		if strings.Contains(line, "ADDR_NACC") {
			t.Logf("First ADDR_NACC at line %d: %s", i, line)
			break
		}
	}

	// Find the first ISYNC for trace ID 0x13 to get starting address
	for _, rec := range expectedRecords {
		if strings.ToLower(rec.ID) == "13" && rec.Kind == helpers.PPLRecordPacket {
			if strings.Contains(rec.Line, "ISYNC") {
				t.Logf("First ISYNC packet: %s", rec.Line)
				break
			}
		}
	}
}

func TestTC2MemoryRange(t *testing.T) {
	// Check what address range TC2 expects to access
	snapshotPath := "../../decoder/tests/snapshots/TC2"
	pplPath := "../../decoder/tests/results/TC2.ppl"

	// Load expected records
	expectedRecords, err := helpers.LoadPPLRecords(pplPath)
	if err != nil {
		t.Fatalf("Failed to load PPL file: %v", err)
	}

	// Check ADDR_NACC addresses to see what memory we're missing
	for _, rec := range expectedRecords {
		if strings.ToLower(rec.ID) == "13" && rec.Kind == helpers.PPLRecordElement {
			if strings.Contains(rec.Line, "ADDR_NACC") {
				t.Logf("ADDR_NACC: %s", rec.Line)
			}
		}
	}

	// Load memory to check range
	kernelPath := filepath.Join(snapshotPath, "kernel_dump.bin")
	kernelData, err := os.ReadFile(kernelPath)
	if err != nil {
		t.Fatalf("Failed to read kernel dump: %v", err)
	}

	startAddr := uint64(0xC0008000)
	endAddr := startAddr + uint64(len(kernelData))
	t.Logf("Kernel memory range: 0x%X - 0x%X (%d bytes)", startAddr, endAddr, len(kernelData))

	// The ADDR_NACC at 0xc02f5b3a is outside kernel range (0xC0008000 - 0xC0058000)
	// This is expected - we don't have that memory loaded
	testAddr := uint64(0xc02f5b3a)
	if testAddr >= startAddr && testAddr < endAddr {
		t.Logf("Address 0x%X is within kernel range", testAddr)
	} else {
		t.Logf("Address 0x%X is OUTSIDE kernel range (0x%X - 0x%X)", testAddr, startAddr, endAddr)
	}
}

func TestTC2SingleISyncDecode(t *testing.T) {
	// Test decoding from a known ISYNC address
	snapshotPath := "../../decoder/tests/snapshots/TC2"

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

	// Simulate processing ISYNC at 0xc0018d82 (first ISYNC for ID 13)
	isyncPkt := ptm.Packet{
		Type:        ptm.PacketTypeISYNC,
		Address:     0xc0018d82,
		ISA:         common.ISAThumb2,
		ISAValid:    true,
		SecureState: true,
		SecureValid: true,
		ISyncReason: ptm.ISyncPeriodic,
	}

	elems, err := decoder.ProcessPacket(isyncPkt)
	if err != nil {
		t.Fatalf("ISYNC error: %v", err)
	}
	for _, elem := range elems {
		t.Logf("After ISYNC: %s", printer.FormatGenericElement(elem))
	}

	// Now process an E atom - should produce an INSTR_RANGE
	atomPkt := ptm.Packet{
		Type:      ptm.PacketTypeATOM,
		AtomCount: 1,
		AtomBits:  1, // E
	}

	elems, err = decoder.ProcessPacket(atomPkt)
	if err != nil {
		t.Fatalf("ATOM error: %v", err)
	}
	for _, elem := range elems {
		line := printer.FormatGenericElementLine(0, 0x13, elem)
		t.Logf("After ATOM: %s", line)
	}

	// Expected from PPL for first E atom:
	// OCSD_GEN_TRC_ELEM_INSTR_RANGE(exec range=0xc0018d82:[0xc0018d8a] num_i(3) last_sz(2) (ISA=T32) E BR   <cond> [CC=522]; )
	expected := "exec range=0xc0018d82:[0xc0018d8a] num_i(3)"
	if len(elems) > 0 {
		line := printer.FormatGenericElement(elems[len(elems)-1])
		if !strings.Contains(line, expected) {
			t.Errorf("Expected output containing %q, got %s", expected, line)
		} else {
			t.Logf("✓ Output matches expected")
		}
	} else {
		t.Error("No elements produced")
	}
}

func TestTC2NaccAddress(t *testing.T) {
	// Test that we correctly produce ADDR_NACC for unmapped addresses
	snapshotPath := "../../decoder/tests/snapshots/TC2"

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

	// Process ISYNC to get to the address before NACC
	// From TC2.ppl, the NACC at 0xc02f5b3a happens after branching to that address
	// The branch to 0xc02f5b3a is from 0xc00185a2

	// First ISYNC at 0xc0018d82
	decoder.ProcessPacket(ptm.Packet{
		Type:        ptm.PacketTypeISYNC,
		Address:     0xc0018d82,
		ISA:         common.ISAThumb2,
		ISAValid:    true,
		SecureState: true,
		SecureValid: true,
		ISyncReason: ptm.ISyncPeriodic,
	})

	// Branch to 0xC00185A2
	decoder.ProcessPacket(ptm.Packet{
		Type:     ptm.PacketTypeBranchAddr,
		Address:  0xc00185a2,
		AddrBits: 32,
	})

	// Branch to 0xC02F5B3A (this address is outside kernel range)
	elems, _ := decoder.ProcessPacket(ptm.Packet{
		Type:     ptm.PacketTypeBranchAddr,
		Address:  0xc02f5b3a,
		AddrBits: 32,
	})

	for _, elem := range elems {
		line := printer.FormatGenericElementLine(0, 0x13, elem)
		t.Logf("Element: %s", line)
	}

	// Now process an atom - should produce ADDR_NACC since 0xc02f5b3a is not accessible
	atomPkt := ptm.Packet{
		Type:      ptm.PacketTypeATOM,
		AtomCount: 1,
		AtomBits:  1, // E
	}

	elems, err = decoder.ProcessPacket(atomPkt)
	if err != nil {
		t.Fatalf("ATOM error: %v", err)
	}

	foundNacc := false
	for _, elem := range elems {
		line := printer.FormatGenericElementLine(0, 0x13, elem)
		t.Logf("After ATOM at unmapped addr: %s", line)
		if elem.Type == common.ElemTypeAddrNacc {
			foundNacc = true
			// Expected: OCSD_GEN_TRC_ELEM_ADDR_NACC( 0xc02f5b3a; Memspace [0x19:Any S] )
			if elem.NaccAddr != 0xc02f5b3a {
				t.Errorf("Expected NACC addr 0xc02f5b3a, got 0x%x", elem.NaccAddr)
			}
		}
	}

	if !foundNacc {
		t.Error("Expected ADDR_NACC element but none was produced")
	} else {
		t.Log("✓ Correctly produced ADDR_NACC for unmapped address")
	}
}

func TestTC2LineByLine(t *testing.T) {
	// Compare line by line for first N elements
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
	decoder.CycleAccEnable = true // TC2 has cycle accurate tracing enabled

	// Manually create packets matching what we see in TC2.ppl
	// We'll compare first few lines
	packets := []ptm.Packet{
		// ASYNC
		{Type: ptm.PacketTypeASYNC, Offset: 26565},
		// ISYNC at 0xc0018d82
		{
			Type: ptm.PacketTypeISYNC, Offset: 26571,
			Address: 0xc0018d82, ISA: common.ISAThumb2, ISAValid: true,
			SecureState: true, SecureValid: true,
			ISyncReason: ptm.ISyncPeriodic,
		},
		// TIMESTAMP (CC=0)
		{Type: ptm.PacketTypeTimestamp, Offset: 26579, Timestamp: 0x82f9d18bcc, CycleCount: 0, CCValid: true},
		// ATOM E (522 cycles)
		{Type: ptm.PacketTypeATOM, Offset: 26590, AtomCount: 1, AtomBits: 1, CycleCount: 522, CCValid: true},
	}

	var actualLines []string
	for _, pkt := range packets {
		elems, err := decoder.ProcessPacket(pkt)
		if err != nil {
			t.Logf("ProcessPacket error: %v", err)
		}
		for _, elem := range elems {
			actualLines = append(actualLines, printer.FormatGenericElementLine(pkt.Offset, 0x13, elem))
		}
	}

	// Compare
	maxCompare := 10
	if len(actualLines) < maxCompare {
		maxCompare = len(actualLines)
	}
	if len(expectedLines) < maxCompare {
		maxCompare = len(expectedLines)
	}

	matches := 0
	for i := 0; i < maxCompare; i++ {
		if i < len(actualLines) && i < len(expectedLines) {
			if actualLines[i] == expectedLines[i] {
				t.Logf("✓ Line %d matches", i)
				matches++
			} else {
				t.Logf("✗ Line %d mismatch:", i)
				t.Logf("  Expected: %s", expectedLines[i])
				t.Logf("  Actual:   %s", actualLines[i])
			}
		}
	}

	t.Logf("Matched %d/%d lines", matches, maxCompare)
	if len(actualLines) != len(expectedLines) {
		t.Logf("Length mismatch: expected %d, got %d", len(expectedLines), len(actualLines))
	}
}
