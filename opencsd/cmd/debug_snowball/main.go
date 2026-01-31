package main

import (
	"fmt"
	"os"
	"path/filepath"

	"opencsd/frame"
)

func main() {
	snapshotPath := "../decoder/tests/snapshots/Snowball"
	tracePath := filepath.Join(snapshotPath, "cstrace.bin")
	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		fmt.Printf("Failed to read trace: %v\n", err)
		return
	}

	demux := frame.NewDemuxer()
	demux.MemAligned = true
	demux.ResetOn4Sync = true
	streams := demux.Process(traceData)

	data, ok := streams[0x10]
	if !ok {
		fmt.Println("No data for ID 0x10")
		return
	}

	fmt.Printf("ID 0x10 stream length: %d bytes\n", len(data))

	asyncPattern := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
	asyncOffset := -1
	for i := 0; i+6 <= len(data); i++ {
		match := true
		for j := 0; j < 6; j++ {
			if data[i+j] != asyncPattern[j] {
				match = false
				break
			}
		}
		if match {
			asyncOffset = i
			break
		}
	}

	fmt.Printf("First ASYNC offset: %d\n", asyncOffset)

	max := 160
	if len(data) < max {
		max = len(data)
	}
	fmt.Printf("First %d bytes:\n", max)
	for i := 0; i < max; i++ {
		fmt.Printf("%02x ", data[i])
		if (i+1)%16 == 0 {
			fmt.Printf("| %d\n", i-15)
		}
	}
	fmt.Println()
}
