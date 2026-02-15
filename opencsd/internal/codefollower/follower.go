package codefollower

import (
	"opencsd/internal/common"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
)

type CodeFollower struct {
	mapper   *memacc.Mapper
	memSpace memacc.MemSpace
	trcID    uint8

	// Current State
	StRangeAddr uint64
	EnRangeAddr uint64
	NextAddr    uint64
	NextValid   bool

	// Range Information
	InstrCount uint32 // Number of instructions in the current range

	// Last Instruction Info
	Info common.InstrInfo

	// Errors
	NaccPending bool
	NaccAddr    uint64
}

func NewCodeFollower(mapper *memacc.Mapper) *CodeFollower {
	return &CodeFollower{
		mapper: mapper,
	}
}

func (c *CodeFollower) Setup(trcID uint8, memSpace memacc.MemSpace) {
	c.trcID = trcID
	c.memSpace = memSpace
}

// TraceToWaypoint walks the code from addrStart until a Waypoint (Branch) is found
// or a memory error occurs. It populates c.Info with the last instruction.
func (c *CodeFollower) TraceToWaypoint(addrStart uint64, isa common.Isa) error {
	c.StRangeAddr = addrStart
	c.EnRangeAddr = addrStart
	c.Info.InstrAddr = addrStart
	c.Info.ISA = isa
	c.Info.NextISA = isa

	c.InstrCount = 0
	c.NaccPending = false
	c.NextValid = false

	bWPFound := false

	// Loop until Waypoint found or Error
	for !bWPFound && !c.NaccPending {
		// 1. Decode one opcode
		err := c.decodeSingleOpCode()
		if err != nil {
			return err
		}

		// If memory access failed, stop.
		if c.NaccPending {
			break
		}

		c.InstrCount++

		// 2. Update Range End (Exclusive)
		// Point to the instruction *after* the one we just decoded
		c.EnRangeAddr = c.Info.InstrAddr + uint64(c.Info.InstrSize)

		// 3. Check if this instruction is a Waypoint
		// In PTM, any instruction that disrupts linear flow (Branch/Indirect) is a Waypoint.
		if c.Info.Type != common.InstrTypeOther {
			bWPFound = true
		} else {
			// Linear flow: Advance to next instruction
			c.Info.InstrAddr = c.EnRangeAddr
			// Note: We assume ISA doesn't change during linear flow without a special instruction
		}
	}

	return nil
}

func (c *CodeFollower) decodeSingleOpCode() error {
	// Read 4 bytes (Standard fetch size for decode)
	opcode, err := c.mapper.ReadTargetMemory(c.Info.InstrAddr, c.trcID, c.memSpace, 4)
	if err != nil {
		c.NaccPending = true
		c.NaccAddr = c.Info.InstrAddr
		return nil
	}

	c.Info.Opcode = opcode

	// Use the enhanced IDEC logic
	err = idec.DecodeInstruction(&c.Info, c.Info.ISA)
	return err
}
