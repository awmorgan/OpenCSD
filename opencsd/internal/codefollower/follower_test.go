package codefollower

import (
	"encoding/binary"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/memacc"
)

func TestCodeFollower(t *testing.T) {
	// 1. Setup Memory with some A64 instructions
	// 0x1000: NOP
	// 0x1004: B 0x1008 (offset +4)
	// 0x1008: NOP
	mem := make([]byte, 20)
	binary.LittleEndian.PutUint32(mem[0:4], 0xd503201f)
	binary.LittleEndian.PutUint32(mem[4:8], 0x14000001)
	binary.LittleEndian.PutUint32(mem[8:12], 0xd503201f)

	mapper := memacc.NewMapper()
	acc := memacc.NewBufferAccessor(0x1000, mem, memacc.MemSpaceAny)
	mapper.AddAccessor(acc, 0)

	follower := NewCodeFollower(mapper)
	follower.Setup(0, memacc.MemSpaceAny)

	t.Run("Follow to Waypoint", func(t *testing.T) {
		err := follower.TraceToWaypoint(0x1000, common.IsaA64, TraceMatchWaypoint, 0)
		if err != nil {
			t.Fatalf("TraceToWaypoint failed: %v", err)
		}

		// Should stop AT the branch instruction (0x1004)
		// Wait, look at follower.go logic:
		// for !bWPFound ... { decode ... if type != Other { bWPFound = true } }
		// So it decodes 0x1000 (NOP, type=Other), then decodes 0x1004 (B, type=Branch -> bWPFound=true)
		if follower.Info.InstrAddr != 0x1004 {
			t.Errorf("Expected to stop at 0x1004, got 0x%x", follower.Info.InstrAddr)
		}

		if follower.InstrCount != 2 {
			t.Errorf("Expected 2 instructions, got %d", follower.InstrCount)
		}

		if follower.Info.Type != common.InstrTypeBranch {
			t.Errorf("Expected type Branch, got %v", follower.Info.Type)
		}
	})

	t.Run("Follow with MatchAddrExcl", func(t *testing.T) {
		// Stop before executing 0x1004
		err := follower.TraceToWaypoint(0x1000, common.IsaA64, TraceMatchAddrExcl, 0x1004)
		if err != nil {
			t.Fatalf("TraceToWaypoint failed: %v", err)
		}

		// Should stop after decoding 0x1000 because EnRangeAddr (0x1004) == matchAddr
		if follower.Info.InstrAddr != 0x1000 {
			t.Errorf("Expected to stop at 0x1000, got 0x%x", follower.Info.InstrAddr)
		}

		if follower.InstrCount != 1 {
			t.Errorf("Expected 1 instruction, got %d", follower.InstrCount)
		}
	})
}
