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
	Decoders    map[uint8]*ptm.PtmDecoder
}

func NewDecodeTree(snapConfig *snapshot.SnapshotConfig, baseDir string) (*DecodeTree, error) {
	tree := &DecodeTree{
		Mapper:      memacc.NewMapper(),
		Deformatter: formatter.NewDeformatter(),
		Printer:     printers.NewPktPrinter(),
		Decoders:    make(map[uint8]*ptm.PtmDecoder),
	}

	// 1. Setup Memory
	if err := tree.setupMemory(snapConfig, baseDir); err != nil {
		return nil, fmt.Errorf("memory setup failed: %v", err)
	}

	// 2. Setup Decoders
	if err := tree.setupDecoders(snapConfig); err != nil {
		return nil, fmt.Errorf("decoder setup failed: %v", err)
	}

	return tree, nil
}

func (t *DecodeTree) setupMemory(cfg *snapshot.SnapshotConfig, baseDir string) error {
	t.Mapper.EnableCaching(true)

	// Deduplication map to prevent adding the same memory dump multiple times
	// (e.g. multi-core snapshots often define the same RAM for every core)
	seen := make(map[string]bool)

	for _, dev := range cfg.Devices {
		for _, dump := range dev.Dumps {
			fullPath := filepath.Join(baseDir, dump.FilePath)

			space := memacc.MemSpaceAny
			if strings.Contains(dump.Space, "S") {
				space = memacc.MemSpaceS
			}
			if strings.Contains(dump.Space, "NS") {
				space = memacc.MemSpaceN
			}

			// Deduplicate
			key := fmt.Sprintf("%s|%d|%d", fullPath, dump.Address, space)
			if seen[key] {
				continue
			}
			seen[key] = true

			acc, err := memacc.NewFileAccessor(fullPath, dump.Address, 0, 0, space)
			if err != nil {
				fmt.Printf("Warning: Could not load dump %s: %v\n", fullPath, err)
				continue
			}

			if err := t.Mapper.AddAccessor(acc, 0); err != nil {
				return err
			}
			fmt.Printf("Loaded Memory: %s @ 0x%X (%s)\n", dump.FilePath, dump.Address, space)
		}
	}
	return nil
}

func (t *DecodeTree) setupDecoders(cfg *snapshot.SnapshotConfig) error {
	if cfg.Trace == nil {
		return fmt.Errorf("no trace metadata in snapshot")
	}

	for _, dev := range cfg.Devices {
		if strings.Contains(dev.Type, "PTM") || strings.Contains(dev.Type, "ETM") {
			trcID := t.getTraceIDFromRegs(dev.Registers)
			if trcID > 0 {
				fmt.Printf("Creating PTM Decoder for %s (ID: 0x%X)\n", dev.Name, trcID)

				decoder := ptm.NewPtmDecoder(t.Printer, t.Mapper)

				// Attach to Deformatter
				t.Deformatter.Attach(trcID, decoder)
				t.Decoders[trcID] = decoder
			}
		}
	}
	return nil
}

func (t *DecodeTree) getTraceIDFromRegs(regs map[string][]snapshot.RegisterValue) uint8 {
	for name, vals := range regs {
		if strings.Contains(name, "TRACEID") && len(vals) > 0 {
			valStr := vals[0].Value
			val, err := strconv.ParseUint(valStr, 0, 8)
			if err == nil {
				return uint8(val)
			}
		}
	}
	return 0
}

func (t *DecodeTree) ProcessBuffer(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fmt.Printf("Processing Trace Buffer: %s (%d bytes)\n", path, len(data))

	_, _, err = t.Deformatter.TraceDataIn(common.OpData, 0, data)
	return err
}
