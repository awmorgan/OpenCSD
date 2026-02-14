package pipeline

import (
	"fmt"
	"io"
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

	out         io.Writer
	decode      bool
	noTimePrint bool
}

func NewDecodeTree(snapConfig *snapshot.SnapshotConfig, baseDir string) (*DecodeTree, error) {
	tree := &DecodeTree{
		Mapper:      memacc.NewMapper(),
		Deformatter: formatter.NewDeformatter(),
		Printer:     printers.NewPktPrinter(),
		Decoders:    make(map[uint8]*ptm.PtmDecoder),
		out:         os.Stdout,
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

func (t *DecodeTree) SetOutput(w io.Writer) {
	t.out = w
	t.Printer.SetOutput(w)
}

func (t *DecodeTree) SetDecode(decode bool) {
	t.decode = decode
	// Note: In a full implementation, this would switch between
	// packet printing and generic element printing.
	// For now, our pipeline defaults to decoded elements.
}

func (t *DecodeTree) SetNoTimePrint(noTime bool) {
	t.noTimePrint = noTime
}

func (t *DecodeTree) setupMemory(cfg *snapshot.SnapshotConfig, baseDir string) error {
	t.Mapper.EnableCaching(true)

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

				decoder := ptm.NewPtmDecoder(t.Printer, t.Mapper)

				t.Deformatter.Attach(trcID, decoder)
				t.Decoders[trcID] = decoder
			}
		}
	}
	return nil
}

func (t *DecodeTree) getTraceIDFromRegs(regs map[string][]snapshot.RegisterValue) uint8 {
	for name, vals := range regs {
		if strings.Contains(strings.ToLower(name), "trcid") && len(vals) > 0 {
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

	_, _, err = t.Deformatter.TraceDataIn(common.OpData, 0, data)
	return err
}

func (t *DecodeTree) PrintGenInfo(w io.Writer) {
	// 1. Print Protocol Printers
	for id := range t.Decoders {
		// Note: C++ prints this for every PTM decoder attached
		fmt.Fprintf(w, "Trace Packet Lister : Protocol printer PTM on Trace ID 0x%X\n", id)
		fmt.Fprintln(w, "Trace Packet Lister : Set trace element decode printer")
	}

	// 2. Print Memory Accessors
	fmt.Fprintln(w, "Gen_Info : Mapped Memory Accessors")
	for _, acc := range t.Mapper.GetAccessors() {
		fmt.Fprintf(w, "Gen_Info : %s\n", acc.String())
	}

	// 3. Print the separator
	fmt.Fprintln(w, "Gen_Info : ========================")
}
