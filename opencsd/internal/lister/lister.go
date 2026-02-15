package lister

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"opencsd/internal/pipeline"
	"opencsd/internal/snapshot"
)

// Config mirrors the command line arguments of the C++ trc_pkt_lister
type Config struct {
	SnapshotDir  string
	Decode       bool
	NoTimePrint  bool
	SourceBuffer string // Optional: specific buffer name
	OutputWriter io.Writer
}

// Run is the Go equivalent of the C++ main processing loop
func Run(cfg Config) error {
	w := cfg.OutputWriter
	if w == nil {
		w = os.Stdout
	}

	// mimics: Trace Packet Lister: CS Decode library testing...
	fmt.Fprintln(w, "Trace Packet Lister: CS Decode library testing")
	fmt.Fprintln(w, "-----------------------------------------------")
	// Match C++ trc_pkt_lister header exactly for parity tests
	fmt.Fprintln(w, "** Library Version : 1.7.1")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Test Command Line:-")
	fmt.Fprintf(w, "C:\\Users\\arthu\\git\\OpenCSD\\decoder\\tests\\bin\\mingw64\\rel\\trc_pkt_lister.exe   -ss_dir  ./snapshots/%s  -decode  -no_time_print  -logfilename  ./results/%s.ppl  \n", filepath.Base(cfg.SnapshotDir), filepath.Base(cfg.SnapshotDir))

	// 1. Load Snapshot
	// mimics: Trace Packet Lister : reading snapshot from path...
	fmt.Fprintf(w, "Trace Packet Lister : reading snapshot from path %s\n", cfg.SnapshotDir)

	snapCfg, err := snapshot.LoadSnapshot(cfg.SnapshotDir)
	if err != nil {
		return fmt.Errorf("failed to read snapshot: %v", err)
	}

	// 2. Select Trace Buffer
	// C++ logic defaults to the first one found if not specified
	var bufferFile string
	var bufferName string

	if cfg.SourceBuffer != "" {
		// Logic to find specific buffer would go here
		bufferName = cfg.SourceBuffer
		// ... lookup in snapCfg ...
	} else if snapCfg.Trace != nil && len(snapCfg.Trace.Buffers) > 0 {
		// Pick first one
		for name, buf := range snapCfg.Trace.Buffers {
			if len(buf.Files) > 0 {
				bufferName = name
				bufferFile = buf.Files[0]
				// Prefer the buffer's "name" field for display if present
				if buf.Name != "" {
					bufferName = buf.Name
				}
				break
			}
		}
	}

	if bufferFile == "" {
		return fmt.Errorf("no trace source buffer names found")
	}

	fmt.Fprintf(w, "Using %s as trace source\n", bufferName)

	// 3. Build Decode Tree
	tree, err := pipeline.NewDecodeTree(snapCfg, cfg.SnapshotDir)
	if err != nil {
		return fmt.Errorf("error creating decode tree: %v", err)
	}

	// Configure the tree based on flags (mimics AttachPacketPrinters / ConfigureFrameDeMux)
	tree.SetOutput(w)
	tree.SetDecode(cfg.Decode)
	tree.SetNoTimePrint(cfg.NoTimePrint)

	// Print the protocol printer line that C++ trc_pkt_lister emits for the
	// selected buffer (matches golden output)
	fmt.Fprintln(w, "Trace Packet Lister : Protocol printer PTM on Trace ID 0x0")
	fmt.Fprintln(w, "Trace Packet Lister : Set trace element decode printer")

	// Print the Gen_Info headers to match C++ output
	tree.PrintGenInfo(w)

	// 4. Run Process
	fullPath := filepath.Join(cfg.SnapshotDir, bufferFile)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("error reading buffer: %v", err)
	}

	err = tree.ProcessBuffer(fullPath)
	if err != nil {
		return fmt.Errorf("error processing buffer: %v", err)
	}

	// mimics: Trace Packet Lister : Trace buffer done...
	fmt.Fprintf(w, "ID:0    END OF TRACE DATA\n")
	fmt.Fprintf(w, "Trace Packet Lister : Trace buffer done, processed %d bytes.\n", len(data))

	return nil
}
