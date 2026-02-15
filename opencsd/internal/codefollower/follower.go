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

// TraceToWaypoint follows instructions starting at addrStart until a Waypoint (Branch)
// is found or memory access fails. This mimics C++ TrcPktDecodePtm::traceInstrToWP.
func (c *CodeFollower) TraceToWaypoint(addrStart uint64, isa common.Isa) error {
	c.StRangeAddr = addrStart
	c.EnRangeAddr = addrStart
	c.Info.InstrAddr = addrStart
	c.Info.ISA = isa
	c.Info.NextISA = isa

	c.NaccPending = false
	c.NextValid = false

	bWPFound := false

	// Loop until we find a waypoint (Branch) or hit a memory error
	for !bWPFound && !c.NaccPending {
		// 1. Decode one opcode
		err := c.decodeSingleOpCode()
		if err != nil {
			return err
		}

		if c.NaccPending {
			break
		}

		// 2. Update Range End (Exclusive)
		c.EnRangeAddr = c.Info.InstrAddr + uint64(c.Info.InstrSize)

		// 3. Check if this instruction is a Waypoint
		// In PTM, any instruction that isn't "Other" (linear flow) is a waypoint.
		if c.Info.Type != common.InstrTypeOther {
			bWPFound = true
		} else {
			// Not a waypoint, advance to next instruction and continue loop
			c.Info.InstrAddr = c.EnRangeAddr
			// Linear flow assumes ISA doesn't change implicitly here
		}
	}

	return nil
}

func (c *CodeFollower) decodeSingleOpCode() error {
	// Read 4 bytes
	opcode, err := c.mapper.ReadTargetMemory(c.Info.InstrAddr, c.trcID, c.memSpace, 4)
	if err != nil {
		c.NaccPending = true
		c.NaccAddr = c.Info.InstrAddr
		return nil // Soft error handled by caller checking NaccPending
	}

	c.Info.Opcode = opcode

	// Use the enhanced IDEC logic
	err = idec.DecodeInstruction(&c.Info, c.Info.ISA)
	return err
}
