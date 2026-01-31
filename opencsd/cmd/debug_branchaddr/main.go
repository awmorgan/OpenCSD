package main

import (
	"fmt"
	"os"
	"path/filepath"

	"opencsd/frame"
	"opencsd/ptm"
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

	data := streams[0x10]
	data = trimToFirstAsync(data)

	dec := ptm.NewDecoder(0x10)
	if _, err := dec.ConfigureFromSnapshot(snapshotPath); err != nil {
		fmt.Printf("Config error: %v\n", err)
		return
	}

	packets, err := dec.Parse(data)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	for i := 0; i+3 <= len(data); i++ {
		if data[i] == 0x72 {
			fmt.Printf("WP_UPDATE raw bytes at %d: %02x %02x %02x\n", i, data[i], data[i+1], data[i+2])
			break
		}
	}

	count := 0
	for _, pkt := range packets {
		if pkt.Type == ptm.PacketTypeBranchAddr {
			fmt.Printf("BranchAddr: data=% x addr=0x%x bits=%d ISA=%v ISAValid=%v CCValid=%v CC=%d\n", pkt.Data, pkt.Address, pkt.AddrBits, pkt.ISA, pkt.ISAValid, pkt.CCValid, pkt.CycleCount)
			count++
			if count >= 3 {
				break
			}
		}
	}
}

func trimToFirstAsync(data []byte) []byte {
	if len(data) < 6 {
		return data
	}
	asyncPattern := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
	for i := 0; i+6 <= len(data); i++ {
		match := true
		for j := 0; j < 6; j++ {
			if data[i+j] != asyncPattern[j] {
				match = false
				break
			}
		}
		if match {
			return data[i:]
		}
	}
	return data
}
