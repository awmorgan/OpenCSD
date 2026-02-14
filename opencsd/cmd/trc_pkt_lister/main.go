package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"opencsd/internal/pipeline"
	"opencsd/internal/snapshot"
)

func main() {
	snapshotDir := flag.String("ss_dir", "", "Path to the snapshot directory")
	flag.Parse()

	if *snapshotDir == "" {
		fmt.Println("Please provide a snapshot directory using -ss_dir")
		os.Exit(1)
	}

	// 1. Load Snapshot Configuration
	fmt.Println("Loading Snapshot...")
	cfg, err := snapshot.LoadSnapshot(*snapshotDir)
	if err != nil {
		fmt.Printf("Error loading snapshot: %v\n", err)
		os.Exit(1)
	}

	// 2. Build Decode Pipeline
	fmt.Println("Building Decode Tree...")
	tree, err := pipeline.NewDecodeTree(cfg, *snapshotDir)
	if err != nil {
		fmt.Printf("Error creating decode tree: %v\n", err)
		os.Exit(1)
	}

	// 3. Find Trace Buffer File (assuming buffer 0 for simplicity)
	if cfg.Trace == nil || len(cfg.Trace.Buffers) == 0 {
		fmt.Println("No trace buffers found in snapshot.")
		os.Exit(1)
	}

	// Just grab the first buffer available
	var bufferFile string
	for _, buf := range cfg.Trace.Buffers {
		if len(buf.Files) > 0 {
			bufferFile = buf.Files[0]
			break
		}
	}

	if bufferFile == "" {
		fmt.Println("No binary trace file defined in snapshot configuration.")
		os.Exit(1)
	}

	// 4. Run Decode
	fullPath := filepath.Join(*snapshotDir, bufferFile)
	err = tree.ProcessBuffer(fullPath)
	if err != nil {
		fmt.Printf("Error processing buffer: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Decode Complete.")
}
