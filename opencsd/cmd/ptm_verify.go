package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"opencsd/common"
	"opencsd/ptm"
)

func loadMemorySnapshot(snapshotPath string) (common.MemoryAccessor, error) {
	memMap := common.NewMultiRegionMemory()

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
			return nil, fmt.Errorf("failed to load memory region %s: %w", region.file, err)
		}
		memMap.AddRegion(common.NewMemoryBuffer(region.addr, data))
		fmt.Printf("Loaded: 0x%08X - 0x%08X (%s, %d bytes)\n",
			region.addr, region.addr+uint64(len(data)), region.file, len(data))
	}

	return memMap, nil
}

func main() {
	snapshotPath := flag.String("snapshot", "../../decoder/tests/snapshots/tc2-ptm-rstk-t32", "Path to PTM snapshot")
	outputFile := flag.String("output", "", "Output file for comparison (optional)")
	maxPackets := flag.Int("max-packets", 100, "Maximum packets to decode")
	flag.Parse()

	// Load trace
	tracePath := filepath.Join(*snapshotPath, "PTM_0_2.bin")
	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load trace: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded trace: %d bytes\n\n", len(traceData))

	// Load memory
	memAcc, err := loadMemorySnapshot(*snapshotPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load memory: %v\n", err)
		os.Exit(1)
	}

	// Create packet parser - reuse decoder for parsing
	packetParser := ptm.NewDecoder(0x0)

	// Parse all packets
	fmt.Println("\nParsing packets...")
	packets, err := packetParser.Parse(traceData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing packets: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed %d packets\n\n", len(packets))

	// Create decoder
	decoder := ptm.NewDecoderWithLogger(0x0, common.NewStdLogger(common.SeverityWarning))
	decoder.SetMemoryAccessor(memAcc)

	// Process packets
	allElements := []common.GenericTraceElement{}
	for i, pkt := range packets {
		if i >= *maxPackets {
			break
		}

		// Process packet
		elements, err := decoder.ProcessPacket(pkt)
		if err != nil {
			fmt.Printf("Error processing packet %d: %v\n", i, err)
		}

		allElements = append(allElements, elements...)

		// Print packet info
		fmt.Printf("Pkt %3d: %s -> %d elements\n", i, pkt.Type, len(elements))
	}

	// Print all elements
	fmt.Printf("\nTotal elements: %d\n\n", len(allElements))

	var output *os.File
	if *outputFile != "" {
		output, err = os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer output.Close()
		fmt.Fprintf(output, "PTM Decoder Output\n")
		fmt.Fprintf(output, "==================\n\n")
	}

	for i, elem := range allElements {
		line := formatElement(i, elem)
		fmt.Println(line)
		if output != nil {
			fmt.Fprintln(output, line)
		}
	}

	if output != nil {
		fmt.Fprintf(os.Stderr, "Output written to %s\n", *outputFile)
	}
}

func formatElement(idx int, elem common.GenericTraceElement) string {
	switch elem.Type {
	case common.ElemTypeNoSync:
		return fmt.Sprintf("Idx:%d; OCSD_GEN_TRC_ELEM_NO_SYNC", idx)
	case common.ElemTypeTraceOn:
		return fmt.Sprintf("Idx:%d; OCSD_GEN_TRC_ELEM_TRACE_ON [%s]", idx, elem.TraceOnReason)
	case common.ElemTypePeContext:
		return fmt.Sprintf("Idx:%d; OCSD_GEN_TRC_ELEM_PE_CONTEXT (ISA=%s)", idx, elem.Context.ISA)
	case common.ElemTypeAddrRange:
		return fmt.Sprintf("Idx:%d; OCSD_GEN_TRC_ELEM_INSTR_RANGE(exec range=0x%X:[0x%X] num_i(%d) last_sz(%d) (ISA=%s))",
			idx, elem.AddrRange.StartAddr, elem.AddrRange.EndAddr, elem.AddrRange.NumInstr, elem.AddrRange.LastInstrSz, elem.AddrRange.ISA)
	case common.ElemTypeAddrNacc:
		return fmt.Sprintf("Idx:%d; OCSD_GEN_TRC_ELEM_ADDR_NACC( 0x%X; )", idx, elem.NaccAddr)
	case common.ElemTypeTimestamp:
		return fmt.Sprintf("Idx:%d; OCSD_GEN_TRC_ELEM_TIMESTAMP( [ TS=0x%X];  [CC=%d]; )", idx, elem.Timestamp, elem.CycleCount)
	case common.ElemTypeException:
		return fmt.Sprintf("Idx:%d; OCSD_GEN_TRC_ELEM_EXCEPTION(pref ret addr:0x%X; excep num (0x%02X) )", idx, elem.Exception.PrefRetAddr, elem.Exception.Number)
	default:
		return fmt.Sprintf("Idx:%d; UNKNOWN_ELEMENT_TYPE(%d)", idx, elem.Type)
	}
}
