package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"opencsd/internal/common"
	"opencsd/internal/formatter"
	"opencsd/internal/memacc"
	"opencsd/internal/printers"
	"opencsd/internal/ptm"
	"opencsd/internal/snapshot"
)

type DecodeTree struct {
	Mapper      *memacc.Mapper
	Deformatter *formatter.Deformatter
	Printer     *printers.PktPrinter
	Decoders    map[uint8]*ptm.PtmDecoder // Keep track of decoders
}

func NewDecodeTree(snapConfig *snapshot.SnapshotConfig, baseDir string) (*DecodeTree, error) {
	tree := &DecodeTree{
		Mapper:      memacc.NewMapper(),
		Deformatter: formatter.NewDeformatter(),
		Printer:     printers.NewPktPrinter(),
		Decoders:    make(map[uint8]*ptm.PtmDecoder),
	}

	// 1. Setup Memory (load dumps from snapshot)
	if err := tree.setupMemory(snapConfig, baseDir); err != nil {
		return nil, fmt.Errorf("memory setup failed: %v", err)
	}

	// 2. Setup Decoders (map IDs to PTM instances)
	if err := tree.setupDecoders(snapConfig); err != nil {
		return nil, fmt.Errorf("decoder setup failed: %v", err)
	}

	return tree, nil
}

func (t *DecodeTree) setupMemory(cfg *snapshot.SnapshotConfig, baseDir string) error {
	t.Mapper.EnableCaching(true)

	for _, dev := range cfg.Devices {
		for _, dump := range dev.Dumps {
			// Resolve path relative to snapshot dir
			fullPath := filepath.Join(baseDir, dump.FilePath)

			// Determine space (simplified logic)
			space := memacc.MemSpaceAny
			if strings.Contains(dump.Space, "S") {
				space = memacc.MemSpaceS
			}
			if strings.Contains(dump.Space, "NS") {
				space = memacc.MemSpaceN
			}

			// Create File Accessor
			acc, err := memacc.NewFileAccessor(fullPath, dump.Address, 0, 0)
			if err != nil {
				// Warn but continue? Or fail? Snapshot files might be missing.
				fmt.Printf("Warning: Could not load dump %s: %v\n", fullPath, err)
				continue
			}

			if err := t.Mapper.AddAccessor(acc, 0); err != nil {
				return err
			}
			fmt.Printf("Loaded Memory: %s @ 0x%X\n", dump.FilePath, dump.Address)
		}
	}
	return nil
}

func (t *DecodeTree) setupDecoders(cfg *snapshot.SnapshotConfig) error {
	// Iterate through Core Trace Sources to find IDs and Types
	// In the snapshot, cfg.Trace.CoreTraceSources maps "SourceID" -> "CoreName"
	// We need to map TraceID (from registers) -> Decoder

	if cfg.Trace == nil {
		return fmt.Errorf("no trace metadata in snapshot")
	}

	// Iterate devices to find the ETM/PTM ones and get their TraceID
	for _, dev := range cfg.Devices {
		// Check if it's a trace source (PTM)
		if strings.Contains(dev.Type, "PTM") || strings.Contains(dev.Type, "ETM") {
			// Find Trace ID from registers
			trcID := t.getTraceIDFromRegs(dev.Registers)
			if trcID > 0 {
				fmt.Printf("Creating PTM Decoder for %s (ID: 0x%X)\n", dev.Name, trcID)

				// Create PTM Decoder
				// Note: In C++, the decoder manages the Context (Security state etc).
				// We initialize with defaults.
				decoder := ptm.NewPtmDecoder(t.Printer, t.Mapper)

				// Register with Deformatter
				t.Deformatter.Attach(trcID, decoder)
				t.Decoders[trcID] = decoder
			}
		}
	}
	return nil
}

func (t *DecodeTree) getTraceIDFromRegs(regs map[string][]snapshot.RegisterValue) uint8 {
	// Look for TRCTRACEIDR or similar
	// PTM 1.x / ETM 3.x usually uses register 0x200 or name "ETMTraceIDR"
	// Snapshot INI usually has names like "TRCTRACEIDR" or just keys.

	// Simplification: Iterate keys looking for ID register
	for name, vals := range regs {
		if strings.Contains(name, "TRACEID") && len(vals) > 0 {
			valStr := vals[0].Value
			// Parse hex string "0x10"
			val, err := strconv.ParseUint(valStr, 0, 8)
			if err == nil {
				return uint8(val)
			}
		}
	}
	return 0
}

// ProcessBuffer processes a raw binary trace file
func (t *DecodeTree) ProcessBuffer(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fmt.Printf("Processing Trace Buffer: %s (%d bytes)\n", path, len(data))

	// Push to Deformatter
	_, _, err = t.Deformatter.TraceDataIn(common.OpData, 0, data)
	return err
}
