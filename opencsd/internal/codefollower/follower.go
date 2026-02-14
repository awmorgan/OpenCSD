package codefollower

import (
	"opencsd/internal/common"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
)

type InstrInfo struct {
	InstrAddr     uint64
	Opcode        uint32
	InstrSize     uint8
	ISA           common.Isa
	NextISA       common.Isa
	Type          int // 0: Other, 1: Branch, 2: Indirect Branch
	SubType       int
	IsConditional bool
	IsLink        bool
	BranchAddr    uint64
}

const (
	InstrTypeOther    = 0
	InstrTypeBranch   = 1
	InstrTypeIndirect = 2
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
	Info InstrInfo

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
// addrStart: The address to start decoding from.
// atom: 'E' (executed) or 'N' (not executed).
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
	// Default: Next instruction
	c.NextAddr = c.EnRangeAddr
	c.NextValid = true

	// Handle Branching
	switch c.Info.Type {
	case InstrTypeBranch:
		if atomVal == common.AtomE {
			c.NextAddr = c.Info.BranchAddr
			c.Info.NextISA = c.decodeISAFromAddr(c.Info.BranchAddr) // helper for Thumb bit
		}
	case InstrTypeIndirect:
		if atomVal == common.AtomE {
			c.NextValid = false // We don't know where an indirect branch goes without more trace info
		}
	}

	return nil
}

func (c *CodeFollower) decodeSingleOpCode() error {
	// Read 4 bytes (even for Thumb, simpler)
	// Note: We use ReadTargetMemory which returns LE uint32
	opcode, err := c.mapper.ReadTargetMemory(c.Info.InstrAddr, c.trcID, c.memSpace, 4)
	if err != nil {
		c.NaccPending = true
		c.NaccAddr = c.Info.InstrAddr
		return nil // Return nil, let upper layer handle NACC via NaccPending flag
	}

	c.Info.Opcode = opcode

	// Decode based on ISA
	dInfo := &idec.DecodeInfo{}
	c.Info.Type = InstrTypeOther
	c.Info.IsConditional = false
	c.Info.IsLink = false
	c.Info.SubType = idec.SubTypeNone

	switch c.Info.ISA {
	case common.IsaA64:
		c.Info.InstrSize = 4
		if idec.InstA64IsBranch(opcode, dInfo) {
			if idec.InstA64IsDirectBranch(opcode, dInfo) {
				c.Info.Type = InstrTypeBranch
				dest, ok := idec.InstA64BranchDestination(c.Info.InstrAddr, opcode)
				if ok {
					c.Info.BranchAddr = dest
				}
			} else {
				c.Info.Type = InstrTypeIndirect
			}
			c.Info.IsConditional = idec.InstA64IsConditional(opcode)
		}
	case common.IsaArm32:
		c.Info.InstrSize = 4
		if idec.InstArmIsBranch(opcode, dInfo) {
			if idec.InstArmIsDirectBranch(opcode) {
				c.Info.Type = InstrTypeBranch
				dest, ok := idec.InstArmBranchDestination(uint32(c.Info.InstrAddr), opcode)
				if ok {
					c.Info.BranchAddr = uint64(dest)
				}
			} else {
				c.Info.Type = InstrTypeIndirect
			}
			c.Info.IsConditional = idec.InstArmIsConditional(opcode)
		}
	case common.IsaThumb:
		// Check for 32-bit Thumb
		is32 := (opcode & 0xF800) >= 0xE800
		if is32 {
			c.Info.InstrSize = 4
			// Swap halves for decoding if read as Little Endian 32-bit int
			// T32 instruction: HW1 HW2. Memory: HW1_L, HW1_H, HW2_L, HW2_H
			// ReadTargetMemory gives: 0xHW2HW1.
			// idec expects: 0xHW1HW2 for 32-bit checks
			hw1 := opcode & 0xFFFF
			hw2 := opcode >> 16
			opcode32 := (hw1 << 16) | hw2

			if idec.InstThumbIsBranch(opcode32, dInfo) {
				if idec.InstThumbIsDirectBranch(opcode32, dInfo) {
					c.Info.Type = InstrTypeBranch
					dest, ok := idec.InstThumbBranchDestination(uint32(c.Info.InstrAddr), opcode32)
					if ok {
						c.Info.BranchAddr = uint64(dest)
					}
				} else {
					c.Info.Type = InstrTypeIndirect
				}
				c.Info.IsConditional = idec.InstThumbIsConditional(opcode32)
			}
		} else {
			c.Info.InstrSize = 2
			// Use low half word, put in high half for decoder
			opcode16 := (opcode & 0xFFFF) << 16
			if idec.InstThumbIsBranch(opcode16, dInfo) {
				if idec.InstThumbIsDirectBranch(opcode16, dInfo) {
					c.Info.Type = InstrTypeBranch
					dest, ok := idec.InstThumbBranchDestination(uint32(c.Info.InstrAddr), opcode16)
					if ok {
						c.Info.BranchAddr = uint64(dest)
					}
				} else {
					c.Info.Type = InstrTypeIndirect
				}
				c.Info.IsConditional = idec.InstThumbIsConditional(opcode16)
			}
		}
	}

	c.Info.SubType = dInfo.InstrSubType
	c.Info.IsLink = (dInfo.InstrSubType == idec.SubTypeBrLink)

	return nil
}

func (c *CodeFollower) decodeISAFromAddr(addr uint64) common.Isa {
	// For ARM/Thumb, LSB indicates Thumb state
	if c.Info.ISA == common.IsaA64 {
		return common.IsaA64
	}
	if (addr & 1) == 1 {
		return common.IsaThumb
	}
	return common.IsaArm32
}
