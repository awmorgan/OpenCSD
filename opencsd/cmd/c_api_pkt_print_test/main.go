// Package main implements c_api_pkt_print_test - tests the C API functionality.
// This is a Go port of the C c_api_pkt_print_test.c utility.
// It tests trace packet printing and decoding using different protocols and configurations.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const capiWiringIncompleteMsg = "c_api_pkt_print_test is a scaffold and is not wired to real protocol decoders yet.\n" +
	"It only performs placeholder parsing and does not validate ETMv3/ETMv4/PTM/STM decoding.\n"

func failIfNotWired() {
	fmt.Fprint(os.Stderr, capiWiringIncompleteMsg)
	os.Exit(2)
}

// TraceProtocol defines supported trace protocols
type TraceProtocol int

const (
	ProtocolETMv4I TraceProtocol = iota
	ProtocolETMv3
	ProtocolPTM
	ProtocolSTM
	ProtocolExternal
)

func (p TraceProtocol) String() string {
	switch p {
	case ProtocolETMv4I:
		return "ETMv4I"
	case ProtocolETMv3:
		return "ETMv3"
	case ProtocolPTM:
		return "PTM"
	case ProtocolSTM:
		return "STM"
	case ProtocolExternal:
		return "External"
	default:
		return "Unknown"
	}
}

// TestOperation defines what operation to perform
type TestOperation int

const (
	OpPacketPrint TestOperation = iota
	OpPacketDecode
	OpPacketDecodeOnly
)

func (op TestOperation) String() string {
	switch op {
	case OpPacketPrint:
		return "Packet Print"
	case OpPacketDecode:
		return "Packet Decode"
	case OpPacketDecodeOnly:
		return "Decode Only"
	default:
		return "Unknown"
	}
}

// Config holds the test configuration
type Config struct {
	Protocol            TraceProtocol
	Operation           TestOperation
	TraceIDOverride     uint8
	UseMemAccCallback   bool
	UseMemAccCallbackID bool
	UseRegionFile       bool
	TestExternalDecoder bool
	OutputRawUnpacked   bool
	OutputRawPacked     bool
	TestPrintStr        bool
	TestLibPrinters     bool
	TestErrorAPI        bool
	OutputStats         bool
	SnapshotPath        string
	LogFileName         string
	DirectBranchCheck   bool
	StrictBranchCheck   bool
	RangeContinuity     bool
	HaltOnError         bool
	SelectedSnapshot    string
	MemDumpAddress      uint64
	TraceDataFile       string
	MemoryDumpFile      string
}

// DefaultConfig creates a default configuration
func DefaultConfig() *Config {
	return &Config{
		Protocol:         ProtocolETMv4I,
		Operation:        OpPacketPrint,
		TraceIDOverride:  0x00,
		OutputStats:      false,
		SnapshotPath:     "./",
		LogFileName:      "c_api_test.log",
		SelectedSnapshot: "/juno_r1_1/",
		MemDumpAddress:   0xFFFFFFC000081000,
		TraceDataFile:    "cstrace.bin",
		MemoryDumpFile:   "kernel_dump.bin",
	}
}

// MemoryAccessor provides access to memory files
type MemoryAccessor struct {
	filePath     string
	data         []byte
	startAddress uint64
	endAddress   uint64
	memSpace     int
	logger       *log.Logger
}

// NewMemoryAccessor creates a new memory accessor
func NewMemoryAccessor(filePath string, startAddr uint64, memSpace int) (*MemoryAccessor, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open memory file: %w", err)
	}

	return &MemoryAccessor{
		filePath:     filePath,
		data:         data,
		startAddress: startAddr,
		endAddress:   startAddr + uint64(len(data)) - 1,
		memSpace:     memSpace,
		logger:       log.New(os.Stdout, "", 0),
	}, nil
}

// ReadMemory reads bytes from the memory at the specified address
func (m *MemoryAccessor) ReadMemory(address uint64, size uint32) ([]byte, error) {
	if address < m.startAddress || address > m.endAddress {
		return nil, fmt.Errorf("address 0x%x out of range [0x%x, 0x%x]",
			address, m.startAddress, m.endAddress)
	}

	offset := address - m.startAddress
	endOffset := offset + uint64(size)

	// Clamp to available data
	if endOffset > uint64(len(m.data)) {
		endOffset = uint64(len(m.data))
	}

	return m.data[offset:endOffset], nil
}

// TracePacket represents a decoded trace packet
type TracePacket struct {
	Index      uint64
	SourceID   uint8
	PacketType string
	Size       uint32
	Data       []byte
	Decoded    bool
	DecodedStr string
}

// String formats the packet for display
func (t TracePacket) String() string {
	if t.Decoded {
		return fmt.Sprintf("[%d] ID:0x%02x %s: %s", t.Index, t.SourceID, t.PacketType, t.DecodedStr)
	}
	return fmt.Sprintf("[%d] ID:0x%02x %s (size: %d)", t.Index, t.SourceID, t.PacketType, t.Size)
}

// TraceDecoder decodes trace packets from a trace data stream
type TraceDecoder struct {
	config    *Config
	traceData []byte
	memAcc    *MemoryAccessor
	packets   []TracePacket
	packetIdx uint64
	logger    *log.Logger
}

// NewTraceDecoder creates a new trace decoder
func NewTraceDecoder(config *Config) *TraceDecoder {
	return &TraceDecoder{
		config:  config,
		packets: make([]TracePacket, 0),
		logger:  log.New(os.Stdout, "", 0),
	}
}

// LoadTraceData loads trace data from a file
func (t *TraceDecoder) LoadTraceData(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to load trace data: %w", err)
	}
	t.traceData = data
	t.logger.Printf("Loaded %d bytes of trace data from %s\n", len(data), filename)
	return nil
}

// LoadMemory loads memory data from a file
func (t *TraceDecoder) LoadMemory(filename string) error {
	var err error
	t.memAcc, err = NewMemoryAccessor(filename, t.config.MemDumpAddress, 0)
	if err != nil {
		return fmt.Errorf("failed to load memory: %w", err)
	}
	t.logger.Printf("Loaded memory from %s at address 0x%x\n", filename, t.config.MemDumpAddress)
	return nil
}

// DecodeTraceData decodes the trace data into packets
func (t *TraceDecoder) DecodeTraceData() error {
	if len(t.traceData) == 0 {
		return fmt.Errorf("no trace data loaded")
	}

	t.logger.Printf("Decoding trace data using protocol %s\n", t.config.Protocol.String())

	// Simple packet extraction - look for packet markers
	for i := 0; i < len(t.traceData); i++ {
		// Look for ID markers (odd values indicate ID bytes)
		if t.traceData[i]%2 == 1 {
			packet := TracePacket{
				Index:      t.packetIdx,
				SourceID:   t.traceData[i] >> 1,
				PacketType: "ID",
				Size:       1,
				Data:       []byte{t.traceData[i]},
				Decoded:    false,
			}
			t.packets = append(t.packets, packet)
			t.packetIdx++

			// Try to read instruction at this ID
			if t.memAcc != nil && i+1 < len(t.traceData) {
				instByte := t.traceData[i+1]
				packet := TracePacket{
					Index:      t.packetIdx,
					SourceID:   t.traceData[i] >> 1,
					PacketType: "DATA",
					Size:       1,
					Data:       []byte{instByte},
					Decoded:    false,
				}
				t.packets = append(t.packets, packet)
				t.packetIdx++
			}
		}
	}

	t.logger.Printf("Extracted %d trace packets\n", len(t.packets))
	return nil
}

// DecodePackets performs full decoding of the packets
func (t *TraceDecoder) DecodePackets() {
	for i := range t.packets {
		if t.packets[i].Decoded {
			continue
		}
		t.packets[i].Decoded = true

		// Simulate decoding
		switch t.packets[i].PacketType {
		case "ID":
			t.packets[i].DecodedStr = fmt.Sprintf("Trace ID: 0x%02x", t.packets[i].Data[0]>>1)
		case "DATA":
			t.packets[i].DecodedStr = fmt.Sprintf("Data: 0x%02x", t.packets[i].Data[0])
		default:
			t.packets[i].DecodedStr = "Unknown packet type"
		}
	}
}

// PrintPackets prints the trace packets
func (t *TraceDecoder) PrintPackets() {
	for _, pkt := range t.packets {
		if t.config.Operation == OpPacketDecodeOnly && !pkt.Decoded {
			continue
		}
		t.logger.Println(pkt.String())
	}
}

// PrintStats prints trace decoding statistics
func (t *TraceDecoder) PrintStats() {
	fmt.Println("\nTrace Decoding Statistics")
	fmt.Println("==========================")
	fmt.Printf("Protocol: %s\n", t.config.Protocol.String())
	fmt.Printf("Total packets: %d\n", len(t.packets))
	fmt.Printf("Decoded packets: ")

	decodedCount := 0
	for _, pkt := range t.packets {
		if pkt.Decoded {
			decodedCount++
		}
	}
	fmt.Printf("%d\n", decodedCount)

	// Count packet types
	typeCounts := make(map[string]int)
	for _, pkt := range t.packets {
		typeCounts[pkt.PacketType]++
	}
	fmt.Println("Packet types:")
	for pktType, count := range typeCounts {
		fmt.Printf("  %s: %d\n", pktType, count)
	}
}

// PrintHelp prints command-line help
func printHelp() {
	fmt.Println("OpenCSD C API Test Program")
	fmt.Println("==========================\n")
	fmt.Println("Usage: c_api_pkt_print_test [options]\n")
	fmt.Println("Protocol Selection (default: etmv4):")
	fmt.Println("  -etmv3              Use ETMv3 protocol")
	fmt.Println("  -ptm                Use PTM protocol")
	fmt.Println("  -stm                Use STM protocol")
	fmt.Println("  -extern             Use external decoder\n")
	fmt.Println("Operation Mode:")
	fmt.Println("  -decode             Decode packets and print both packets and output")
	fmt.Println("  -decode_only        Only print decoded trace output (default: packet print)\n")
	fmt.Println("Memory Access:")
	fmt.Println("  -test_cb            Test callback-based memory access")
	fmt.Println("  -test_cb_id         Test callback-based memory access with trace ID")
	fmt.Println("  -test_region_file   Test multi-region memory file API (default: single file)\n")
	fmt.Println("Output Options:")
	fmt.Println("  -raw                Print raw unpacked trace data")
	fmt.Println("  -raw_packed         Print raw packed trace data")
	fmt.Println("  -stats              Print trace statistics\n")
	fmt.Println("Testing:")
	fmt.Println("  -test_printstr      Test print string callback")
	fmt.Println("  -test_libprint      Test library-based packet printers")
	fmt.Println("  -test_err_api       Test error API\n")
	fmt.Println("Trace ID and Configuration:")
	fmt.Println("  -id <ID>            Decode specific trace ID (hex, default 0x10)")
	fmt.Println("  -direct_br_cond     Check direct unconditional branches")
	fmt.Println("  -strict_br_cond     Strict conditional branch checks")
	fmt.Println("  -range_cont         Range continuity checks")
	fmt.Println("  -halt_err           Halt on error packets\n")
	fmt.Println("Paths:")
	fmt.Println("  -ss_path <path>     Path to snapshots directory")
	fmt.Println("  -logfilename <name> Output log filename (default: c_api_test.log)\n")
}

// parseCommandLine parses command-line arguments
func parseCommandLine(args []string) (*Config, error) {
	cfg := DefaultConfig()

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-etmv3":
			cfg.Protocol = ProtocolETMv3
			cfg.SelectedSnapshot = "/TC2/"
			cfg.MemDumpAddress = 0xC0008000
		case "-ptm":
			cfg.Protocol = ProtocolPTM
			cfg.SelectedSnapshot = "/TC2/"
			cfg.MemDumpAddress = 0xC0008000
		case "-stm":
			cfg.Protocol = ProtocolSTM
			cfg.TraceDataFile = "cstraceitm.bin"
		case "-extern":
			cfg.TestExternalDecoder = true
		case "-decode":
			cfg.Operation = OpPacketDecode
		case "-decode_only":
			cfg.Operation = OpPacketDecodeOnly
		case "-id":
			if i+1 < len(args) {
				i++
				if id, err := strconv.ParseUint(args[i], 0, 8); err == nil {
					cfg.TraceIDOverride = uint8(id)
				}
			}
		case "-test_cb":
			cfg.UseMemAccCallback = true
			cfg.UseRegionFile = false
		case "-test_cb_id":
			cfg.UseMemAccCallback = true
			cfg.UseMemAccCallbackID = true
			cfg.UseRegionFile = false
		case "-test_region_file":
			cfg.UseRegionFile = true
			cfg.UseMemAccCallback = false
		case "-raw":
			cfg.OutputRawUnpacked = true
		case "-raw_packed":
			cfg.OutputRawPacked = true
		case "-test_printstr":
			cfg.TestPrintStr = true
		case "-test_libprint":
			cfg.TestLibPrinters = true
		case "-test_err_api":
			cfg.TestErrorAPI = true
		case "-stats":
			cfg.OutputStats = true
		case "-direct_br_cond":
			cfg.DirectBranchCheck = true
		case "-strict_br_cond":
			cfg.StrictBranchCheck = true
		case "-range_cont":
			cfg.RangeContinuity = true
		case "-halt_err":
			cfg.HaltOnError = true
		case "-ss_path":
			if i+1 < len(args) {
				i++
				cfg.SnapshotPath = args[i]
			}
		case "-logfilename":
			if i+1 < len(args) {
				i++
				cfg.LogFileName = args[i]
			}
		case "-help", "-h":
			return nil, fmt.Errorf("help")
		default:
			if !strings.HasPrefix(arg, "-") {
				fmt.Printf("Ignoring unknown argument: %s\n", arg)
			}
		}
	}

	return cfg, nil
}

func main() {
	failIfNotWired()

	// Parse command line
	cfg, err := parseCommandLine(os.Args[1:])
	if err != nil {
		printHelp()
		return
	}

	fmt.Println("OpenCSD C API Trace Test")
	fmt.Println("=======================\n")

	// Build snapshot path
	snapshotPath := filepath.Join(cfg.SnapshotPath, cfg.SelectedSnapshot)
	traceFile := filepath.Join(snapshotPath, cfg.TraceDataFile)
	memFile := filepath.Join(snapshotPath, cfg.MemoryDumpFile)

	// Create decoder
	decoder := NewTraceDecoder(cfg)

	// Load trace data
	if err := decoder.LoadTraceData(traceFile); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Load memory if available
	if _, err := os.Stat(memFile); err == nil {
		if err := decoder.LoadMemory(memFile); err != nil {
			fmt.Printf("Warning: could not load memory - %v\n", err)
		}
	}

	// Decode trace data
	if err := decoder.DecodeTraceData(); err != nil {
		fmt.Printf("Error decoding trace: %v\n", err)
		os.Exit(1)
	}

	// Perform operation
	switch cfg.Operation {
	case OpPacketDecode:
		decoder.DecodePackets()
		fmt.Println("Decoded Packets:")
		fmt.Println("================")
	case OpPacketDecodeOnly:
		decoder.DecodePackets()
		fmt.Println("Trace Output:")
		fmt.Println("=============")
	default:
		fmt.Println("Trace Packets:")
		fmt.Println("==============")
	}

	decoder.PrintPackets()

	// Print statistics if requested
	if cfg.OutputStats {
		decoder.PrintStats()
	}

	fmt.Println("\nTest complete")
}
