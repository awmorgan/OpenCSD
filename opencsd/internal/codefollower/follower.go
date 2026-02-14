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

// FollowSingleAtom follows one instruction for an atom (E or N).
func (c *CodeFollower) FollowSingleAtom(addrStart uint64, atomVal common.AtomVal, isa common.Isa) error {
	c.StRangeAddr = addrStart
	c.EnRangeAddr = addrStart
	c.Info.InstrAddr = addrStart
	c.Info.ISA = isa
	c.Info.NextISA = isa

	c.NaccPending = false
	c.NextValid = false

	// 1. Decode one opcode
	err := c.decodeSingleOpCode()
	if err != nil {
		return err
	}

	// 2. Update Range End (Exclusive)
	c.EnRangeAddr = c.Info.InstrAddr + uint64(c.Info.InstrSize)

	// 3. Calculate Next Address
	// Default: Next instruction sequential
	c.NextAddr = c.EnRangeAddr
	c.NextValid = true

	// Handle Branching
	switch c.Info.Type {
	case common.InstrTypeBranch:
		if atomVal == common.AtomE {
			// Executed direct branch - go to branch destination
			c.NextAddr = c.Info.BranchAddr
			c.Info.NextISA = c.decodeISAFromAddr(c.Info.BranchAddr)
		}
		// If AtomN (Not Executed), we fall through to NextAddr (sequential), which is already set.

	case common.InstrTypeIndirect:
		if atomVal == common.AtomE {
			// Executed indirect branch - We do not know the destination statically.
			// The next address is invalid; the trace decoder must wait for a broadcast address packet.
			c.NextValid = false
		}
		// If AtomN, fall through sequential.
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

func (c *CodeFollower) decodeISAFromAddr(addr uint64) common.Isa {
	// For ARM/Thumb, LSB indicates Thumb state
	// If we are currently A64, we likely stay A64 unless specific interworking (not handled here)
	if c.Info.ISA == common.IsaA64 {
		return common.IsaA64
	}
	if (addr & 1) == 1 {
		return common.IsaThumb
	}
	return common.IsaArm32
}
