package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"opencsd/common"
	"opencsd/ptm"
)

func main() {
	var (
		snapshot = flag.String("snapshot", "../decoder/tests/snapshots/TC2", "path to TC2 snapshot")
		startHex = flag.Uint64("start", 0xC000CD4E, "start address (hex)")
		endHex   = flag.Uint64("end", 0xC000CDA0, "end address (hex, exclusive)")
	)
	flag.Parse()

	kernelPath := filepath.Join(*snapshot, "kernel_dump.bin")
	data, err := os.ReadFile(kernelPath)
	if err != nil {
		fmt.Printf("Failed to read kernel dump: %v\n", err)
		return
	}

	mem := common.NewMultiRegionMemory()
	mem.AddRegion(common.NewMemoryBuffer(0xC0008000, data))

	decoder := ptm.NewInstrDecoder(common.ISAThumb2)
	addr := *startHex
	end := *endHex
	if end <= addr {
		fmt.Printf("Invalid range: start=0x%X end=0x%X\n", addr, end)
		return
	}

	for addr < end {
		info, err := decoder.DecodeInstruction(addr, mem)
		if err != nil {
			fmt.Printf("0x%08X: decode error: %v\n", addr, err)
			break
		}
		fmt.Printf("0x%08X: size=%d type=%s branch=%v link=%v ret=%v opcode=0x%08X\n",
			addr, info.Size, info.Type, info.IsBranch, info.IsLink, info.IsReturn, info.Opcode)
		if info.Size == 0 {
			break
		}
		addr += uint64(info.Size)
	}
}
