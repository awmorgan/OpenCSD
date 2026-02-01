// Package main implements trc_pkt_lister - the main trace packet lister utility.
// This is a Go port of the C++ trc_pkt_lister.cpp utility.
// It reads trace snapshots and lists/decodes trace packets.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const listerWiringIncompleteMsg = "trc_pkt_lister is a scaffold and is not wired to real protocol decoders yet.\n" +
	"It only performs placeholder parsing and does not validate ETMv3/ETMv4/PTM/STM decoding.\n"

func failIfNotWired() {
	fmt.Fprint(os.Stderr, listerWiringIncompleteMsg)
	os.Exit(2)
}

// Config holds command-line configuration
type Config struct {
	SnapshotPath       string
	SourceName         string
	OutputFile         string
	DecodePackets      bool
	DecodeOnly         bool
	OutputRawPacked    bool
	OutputRawUnpacked  bool
	MultiSession       bool
	DStreamFormat      bool
	TPIUFormat         bool
	TPIUHSync          bool
	Stats              bool
	ProfileMode        bool
	NoTimePrint        bool
	HaltOnError        bool
	MemAccCacheDisable bool
	LogToStdout        bool
	LogToStderr        bool
	LogToFile          bool
	IDFilter           []uint8
	ConsistencyChecks  struct {
		AA64OpcodeChk  bool
		DirectBrCond   bool
		StrictBrCond   bool
		RangeCont      bool
	}
	CacheSettings struct {
		PageSize uint32
		PageNum  uint32
	}
}

// SnapshotReader reads trace snapshots
type SnapshotReader struct {
	path string
	log  *log.Logger
}

// NewSnapshotReader creates a new snapshot reader
func NewSnapshotReader(path string) *SnapshotReader {
	return &SnapshotReader{
		path: path,
		log:  log.New(os.Stdout, "", 0),
	}
}

// ReadSnapshot reads a snapshot directory
func (s *SnapshotReader) ReadSnapshot() (map[string]interface{}, error) {
	// Check if snapshot.ini exists
	iniPath := filepath.Join(s.path, "snapshot.ini")
	_, err := os.Stat(iniPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot not found at %s", s.path)
	}

	result := make(map[string]interface{})
	result["path"] = s.path
	result["ini_file"] = iniPath

	return result, nil
}

// GetSourceNames returns available trace source names
func (s *SnapshotReader) GetSourceNames() ([]string, error) {
	// List all .bin files in the snapshot directory
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return nil, err
	}

	var sources []string
	for _, entry := range entries {
		if !entry.IsDir() {
			name := entry.Name()
			if strings.HasSuffix(name, ".bin") {
				sourceName := strings.TrimSuffix(name, ".bin")
				sources = append(sources, sourceName)
			}
		}
	}

	return sources, nil
}

// TracePacket represents a decoded trace packet
type TracePacket struct {
	Index        uint64
	SourceID     uint8
	PacketType   string
	Size         uint32
	Data         []byte
	Decoded      bool
	DecodedInfo  string
}

// String formats the packet for display
func (t TracePacket) String() string {
	if t.Decoded {
		return fmt.Sprintf("[%d] ID:0x%02x Type:%s Info:%s", t.Index, t.SourceID, t.PacketType, t.DecodedInfo)
	}
	return fmt.Sprintf("[%d] ID:0x%02x Type:%s Size:%d", t.Index, t.SourceID, t.PacketType, t.Size)
}

// PacketDecoder decodes trace packets
type PacketDecoder struct {
	log       *log.Logger
	packets   []TracePacket
	packetIdx uint64
}

// NewPacketDecoder creates a new packet decoder
func NewPacketDecoder() *PacketDecoder {
	return &PacketDecoder{
		log:     log.New(os.Stdout, "", 0),
		packets: make([]TracePacket, 0),
	}
}

// DecodeTraceData decodes trace data from a file
func (p *PacketDecoder) DecodeTraceData(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read trace data: %w", err)
	}

	p.log.Printf("Decoding %d bytes of trace data from %s\n", len(data), filename)

	// Simple packet extraction - look for ID markers and data bytes
	i := 0
	for i < len(data) {
		// Simple heuristic: ID bytes have bit 0 set (odd values)
		if data[i]%2 == 1 {
			packet := TracePacket{
				Index:    p.packetIdx,
				SourceID: data[i] >> 1,
				PacketType: "ID",
				Size:     1,
				Data:     []byte{data[i]},
				Decoded:  false,
			}
			p.packets = append(p.packets, packet)
			p.packetIdx++
		} else if i > 0 && data[i-1]%2 == 1 {
			// Data byte following ID
			packet := TracePacket{
				Index:      p.packetIdx,
				SourceID:   data[i-1] >> 1,
				PacketType: "DATA",
				Size:       1,
				Data:       []byte{data[i]},
				Decoded:    false,
			}
			p.packets = append(p.packets, packet)
			p.packetIdx++
		}
		i++
	}

	return nil
}

// DecodePackets decodes the extracted packets
func (p *PacketDecoder) DecodePackets() {
	for i := range p.packets {
		p.packets[i].Decoded = true
		// Simple decoding - in real implementation this would be more complex
		p.packets[i].DecodedInfo = fmt.Sprintf("Payload: %02x", p.packets[i].Data[0])
	}
}

// PrintPackets prints the decoded packets
func (p *PacketDecoder) PrintPackets(config *Config) {
	for _, packet := range p.packets {
		if config.DecodeOnly && !packet.Decoded {
			continue
		}
		p.log.Println(packet.String())
	}
}

// PrintStats prints packet statistics
func (p *PacketDecoder) PrintStats() {
	fmt.Printf("\nPacket Statistics\n")
	fmt.Printf("==================\n")
	fmt.Printf("Total packets: %d\n", len(p.packets))

	// Count by source ID
	idCounts := make(map[uint8]int)
	for _, packet := range p.packets {
		idCounts[packet.SourceID]++
	}

	fmt.Println("Packets by Source ID:")
	for id, count := range idCounts {
		fmt.Printf("  ID 0x%02x: %d packets\n", id, count)
	}
}

// parseCommandLine parses command-line arguments
func parseCommandLine() *Config {
	cfg := &Config{
		SnapshotPath:  "./",
		OutputFile:    "trc_pkt_lister.ppl",
		DecodePackets: false,
		DecodeOnly:    false,
		Stats:         false,
	}

	flag.StringVar(&cfg.SnapshotPath, "snapshot", cfg.SnapshotPath, "Path to snapshot directory")
	flag.StringVar(&cfg.SourceName, "src_name", "", "Specific source name to list")
	flag.StringVar(&cfg.OutputFile, "logfilename", cfg.OutputFile, "Output log filename")
	flag.BoolVar(&cfg.DecodePackets, "decode", false, "Decode packets (default is to list undecoded only)")
	flag.BoolVar(&cfg.DecodeOnly, "decode_only", false, "Only show decoded packets, not raw")
	flag.BoolVar(&cfg.OutputRawPacked, "o_raw_packed", false, "Output raw packed trace frames")
	flag.BoolVar(&cfg.OutputRawUnpacked, "o_raw_unpacked", false, "Output raw unpacked trace data per ID")
	flag.BoolVar(&cfg.MultiSession, "multi_session", false, "List packets from all sources with same config")
	flag.BoolVar(&cfg.DStreamFormat, "dstream_format", false, "Input is DSTREAM framed")
	flag.BoolVar(&cfg.TPIUFormat, "tpiu", false, "Input from TPIU - sync by FSYNC")
	flag.BoolVar(&cfg.TPIUHSync, "tpiu_hsync", false, "Input from TPIU - sync by FSYNC and HSYNC")
	flag.BoolVar(&cfg.Stats, "stats", false, "Output packet processing statistics")
	flag.BoolVar(&cfg.ProfileMode, "profile", false, "Mute logging while profiling")
	flag.BoolVar(&cfg.NoTimePrint, "no_time_print", false, "Do not output elapsed time")
	flag.BoolVar(&cfg.HaltOnError, "halt_err", false, "Halt on bad packet error")
	flag.BoolVar(&cfg.MemAccCacheDisable, "macc_cache_disable", false, "Disable memory accessor caching")
	flag.BoolVar(&cfg.LogToStdout, "logstdout", true, "Log to stdout")
	flag.BoolVar(&cfg.LogToStderr, "logstderr", false, "Log to stderr")
	flag.BoolVar(&cfg.LogToFile, "logfile", false, "Log to file")
	flag.BoolVar(&cfg.ConsistencyChecks.AA64OpcodeChk, "aa64_opcode_chk", false, "Check AA64 opcodes")
	flag.BoolVar(&cfg.ConsistencyChecks.DirectBrCond, "direct_br_cond", false, "Check direct branch conditions")
	flag.BoolVar(&cfg.ConsistencyChecks.StrictBrCond, "strict_br_cond", false, "Strict conditional checks")
	flag.BoolVar(&cfg.ConsistencyChecks.RangeCont, "range_cont", false, "Range continuity checks")

	flag.Parse()

	return cfg
}

// printHelp prints command-line help
func printHelp() {
	fmt.Println("Trace Packet Lister - OpenCSD Library Testing Utility")
	fmt.Println("=====================================================\n")
	fmt.Println("Usage: trc_pkt_lister [options]\n")
	fmt.Println("Options:\n")
	fmt.Println("  -snapshot <path>        Path to trace snapshot directory (default: ./)")
	fmt.Println("  -src_name <name>        Specific source name to list")
	fmt.Println("  -multi_session          List all sources with same config")
	fmt.Println("  -decode                 Full decode (default: list undecoded packets)")
	fmt.Println("  -decode_only            Only show decoded packets")
	fmt.Println("  -o_raw_packed           Output raw packed frames")
	fmt.Println("  -o_raw_unpacked         Output raw unpacked data per ID")
	fmt.Println("  -dstream_format         Input is DSTREAM framed")
	fmt.Println("  -tpiu                   Input from TPIU with FSYNC")
	fmt.Println("  -tpiu_hsync             Input from TPIU with FSYNC and HSYNC")
	fmt.Println("  -stats                  Output statistics")
	fmt.Println("  -no_time_print          Do not output elapsed time")
	fmt.Println("  -halt_err               Halt on error (vs. resync)")
	fmt.Println("  -logstdout              Log to stdout (default)")
	fmt.Println("  -logstderr              Log to stderr")
	fmt.Println("  -logfile                Log to file")
	fmt.Println("  -logfilename <name>     Log to specific file")
	fmt.Println("  -profile                Mute output for profiling")
	fmt.Println("  -h, -help               Show this help message")
}

func main() {
	failIfNotWired()

	cfg := parseCommandLine()

	if flag.NFlag() == 0 {
		printHelp()
		return
	}

	fmt.Println("Trace Packet Lister: CS Decode library testing")
	fmt.Println("----------------------------------------------\n")

	startTime := time.Now()

	// Create snapshot reader
	reader := NewSnapshotReader(cfg.SnapshotPath)

	// Read snapshot
	_, err := reader.ReadSnapshot()
	if err != nil {
		fmt.Printf("Error reading snapshot: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Reading snapshot from path: %s\n\n", cfg.SnapshotPath)

	// Get source names
	sources, err := reader.GetSourceNames()
	if err != nil {
		fmt.Printf("Error reading snapshot sources: %v\n", err)
		os.Exit(1)
	}

	if len(sources) == 0 {
		fmt.Println("Error: No trace sources found in snapshot")
		os.Exit(1)
	}

	// Select source
	sourceName := cfg.SourceName
	if sourceName == "" {
		sourceName = sources[0]
	}

	fmt.Printf("Using source: %s\n", sourceName)

	// Create decoder
	decoder := NewPacketDecoder()

	// Decode trace data
	traceFile := filepath.Join(cfg.SnapshotPath, sourceName+".bin")
	err = decoder.DecodeTraceData(traceFile)
	if err != nil {
		fmt.Printf("Error decoding trace: %v\n", err)
		os.Exit(1)
	}

	// Apply decoding if requested
	if cfg.DecodePackets {
		fmt.Println("Decoding packets...")
		decoder.DecodePackets()
	}

	// Print results
	fmt.Println("\nTrace Packets:")
	fmt.Println("==============")
	decoder.PrintPackets(cfg)

	// Print statistics
	if cfg.Stats {
		decoder.PrintStats()
	}

	// Print elapsed time
	if !cfg.NoTimePrint {
		elapsed := time.Since(startTime)
		fmt.Printf("\nElapsed time: %v\n", elapsed)
	}

	fmt.Println("\nTrace packet listing complete")
}
