package main

import (
	"flag"
	"fmt"
	"os"

	"opencsd/internal/lister"
)

func main() {
	snapshotDir := flag.String("ss_dir", "", "Path to the snapshot directory")
	decode := flag.Bool("decode", false, "Full decode of the packets")
	noTime := flag.Bool("no_time_print", false, "Do not output elapsed time")

	flag.Parse()

	if *snapshotDir == "" {
		fmt.Println("Trace Packet Lister : Error: Missing directory string on -ss_dir option")
		os.Exit(1)
	}

	cfg := lister.Config{
		SnapshotDir:  *snapshotDir,
		Decode:       *decode,
		NoTimePrint:  *noTime,
		OutputWriter: os.Stdout,
	}

	if err := lister.Run(cfg); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
