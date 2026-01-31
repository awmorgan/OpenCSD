package main

import (
	"fmt"
	"os"
	"path/filepath"

	"opencsd/common"
	"opencsd/ptm"
)

func main() {
	snapshotPath := "../decoder/tests/snapshots/Snowball"
	kernelPath := filepath.Join(snapshotPath, "kernel_dump.bin")
	data, err := os.ReadFile(kernelPath)
	if err != nil {
		fmt.Printf("Failed to read kernel dump: %v\n", err)
		return
	}
	mem := common.NewMultiRegionMemory()
	mem.AddRegion(common.NewMemoryBuffer(0xC0008000, data))

	decoder := ptm.NewInstrDecoder(common.ISAARM)
	start := uint64(0xC0010150)
	for i := 0; i < 12; i++ {
		addr := start + uint64(i*4)
		info, err := decoder.DecodeInstruction(addr, mem)
		if err != nil {
			fmt.Printf("0x%08X: decode error: %v\n", addr, err)
			continue
		}
		fmt.Printf("0x%08X: opcode=0x%08X size=%d type=%s branch=%v cond=%v link=%v ret=%v target=0x%X nextISA=%s nextValid=%v\n", addr, info.Opcode, info.Size, info.Type, info.IsBranch, info.IsConditional, info.IsLink, info.IsReturn, info.BranchTarget, info.NextISA, info.NextISAValid)
	}
}
