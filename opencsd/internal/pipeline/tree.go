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
	Mapper         *memacc.Mapper
	Deformatter    *formatter.Deformatter
	Printer        *printers.PktPrinter
	Decoders       map[uint8]*ptm.PtmDecoder
	UseDeformatter bool
	RawDecoder     common.TrcDataIn

	out         io.Writer
	decode      bool
	noTimePrint bool
}

func NewDecodeTree(snapConfig *snapshot.SnapshotConfig, baseDir string) (*DecodeTree, error) {
	tree := &DecodeTree{
		Mapper:         memacc.NewMapper(),
		Deformatter:    formatter.NewDeformatter(),
		Printer:        printers.NewPktPrinter(),
		Decoders:       make(map[uint8]*ptm.PtmDecoder),
		out:            os.Stdout,
		UseDeformatter: true, // default to using deformatter
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

			// Handle Offset and Length from snapshot
			var offset int64
			if dump.Offset != nil {
				offset = int64(*dump.Offset)
			}
			var length int64
			if dump.Length != nil {
				length = int64(*dump.Length)
			}

			key := fmt.Sprintf("%s|%d|%d|%d|%d", fullPath, dump.Address, offset, length, space)
			if seen[key] {
				continue
			}
			seen[key] = true

			acc, err := memacc.NewFileAccessor(fullPath, dump.Address, offset, length, space)
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

	// Create a map from trace source name to decoder trace ID
	sourceNameToTraceID := make(map[string]uint8)

	for _, dev := range cfg.Devices {
		if strings.Contains(dev.Type, "PTM") || strings.Contains(dev.Type, "ETM") || strings.Contains(dev.Type, "PFT") {
			// Determine if a trace ID register exists for this device
			hasTraceID := false
			for regName := range dev.Registers {
				key := strings.ToLower(regName)
				if key == "etmtraceidr" || key == "trctraceidr" {
					hasTraceID = true
					break
				}
			}

			trcID := t.getTraceIDFromRegs(dev.Registers)
			// Create decoder when a trace ID register is present (even if value is 0)
			if hasTraceID {
				decoder := ptm.NewPtmDecoder(t.Printer, t.Mapper)
				t.Deformatter.Attach(trcID, decoder)
				t.Decoders[trcID] = decoder

				// Map device name to trace ID
				sourceNameToTraceID[dev.Name] = trcID
			}
		}
	}

	// Detect buffer format and configure routing
	for _, buf := range cfg.Trace.Buffers {
		// If format is "source_data" or empty (raw), bypass deformatter
		if buf.Format == "source_data" || buf.Format == "" {
			t.UseDeformatter = false

			// Find the trace source(s) for this buffer using the buffer's Name field
			if sourceSources, ok := cfg.Trace.SourceBuffers[buf.Name]; ok && len(sourceSources) > 0 {
				sourceName := sourceSources[0]

				// Find the device with this source name
				if traceID, ok := sourceNameToTraceID[sourceName]; ok {
					if decoder, ok := t.Decoders[traceID]; ok {
						t.RawDecoder = decoder
					}
				}
			}
		}
		break // Process only first buffer for now
	}

	return nil
}

func (t *DecodeTree) getTraceIDFromRegs(regs map[string][]snapshot.RegisterValue) uint8 {
	valid := map[string]struct{}{
		"etmtraceidr": {},
		"trctraceidr": {},
	}
	for name, vals := range regs {
		key := strings.ToLower(name)
		if _, ok := valid[key]; ok && len(vals) > 0 {
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

	if t.UseDeformatter {
		_, _, err = t.Deformatter.TraceDataIn(common.OpData, 0, data)
		if err != nil {
			return err
		}
		// Signal end of trace to flush any remaining data
		_, _, err = t.Deformatter.TraceDataIn(common.OpEOT, int64(len(data)), nil)
	} else {
		// Raw bypass: feed directly to the decoder
		if t.RawDecoder != nil {
			_, _, err = t.RawDecoder.TraceDataIn(common.OpData, 0, data)
			if err != nil {
				return err
			}
			// Signal end of trace to flush any remaining data
			_, _, err = t.RawDecoder.TraceDataIn(common.OpEOT, int64(len(data)), nil)
		} else {
			return fmt.Errorf("raw format detected but no decoder attached")
		}
	}
	return err
}

func (t *DecodeTree) PrintGenInfo(w io.Writer) {
	// 1. Print Memory Accessors
	fmt.Fprintln(w, "Gen_Info : Mapped Memory Accessors")
	for _, acc := range t.Mapper.GetAccessors() {
		fmt.Fprintf(w, "Gen_Info : %s\n", acc.String())
	}

	// 2. Print the separator
	fmt.Fprintln(w, "Gen_Info : ========================")
}
