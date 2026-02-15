package codefollower

import (
	"opencsd/internal/common"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
)

// TraceMatchMode defines how the code follower determines when to stop.
type TraceMatchMode int

const (
	TraceMatchWaypoint TraceMatchMode = 0 // Run until a Waypoint instruction (Branch, etc.)
	TraceMatchAddrExcl TraceMatchMode = 1 // Run until NextAddr == MatchAddr (MatchAddr is NOT executed)
	TraceMatchAddrIncl TraceMatchMode = 2 // Run until InstrAddr == MatchAddr (MatchAddr IS executed)
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

	// Range Info
	InstrCount uint32

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

// TraceToWaypoint follows instructions starting at addrStart.
// It stops based on the matchMode:
// - TraceMatchWaypoint: Stops when a Waypoint (Branch, etc.) is found.
// - TraceMatchAddrExcl: Stops before executing matchAddr.
// - TraceMatchAddrIncl: Stops after executing matchAddr.
func (c *CodeFollower) TraceToWaypoint(addrStart uint64, isa common.Isa, matchMode TraceMatchMode, matchAddr uint64) error {
	c.StRangeAddr = addrStart
	c.EnRangeAddr = addrStart
	c.Info.InstrAddr = addrStart
	c.Info.ISA = isa
	c.Info.NextISA = isa

	c.InstrCount = 0
	c.NaccPending = false
	c.NextValid = false

	bWPFound := false

	// Loop until we find a waypoint/match or hit a memory error
	for !bWPFound && !c.NaccPending {
		// 1. Decode one opcode at c.Info.InstrAddr
		// Note: This logic mimics C++ traceInstrToWP loop structure
		err := c.decodeSingleOpCode()
		if err != nil {
			return err
		}

		if c.NaccPending {
			break
		}

		// Update range stats
		c.InstrCount++

		// 2. Update Range End (Exclusive)
		// Point to the instruction *after* the one we just decoded
		c.EnRangeAddr = c.Info.InstrAddr + uint64(c.Info.InstrSize)

		// 3. Check for Stop Condition
		if matchMode != TraceMatchWaypoint {
			if matchMode == TraceMatchAddrExcl {
				// Exclusive: Stop if the NEXT address matches
				bWPFound = (c.EnRangeAddr == matchAddr)
			} else {
				// Inclusive: Stop if the CURRENT address matches
				bWPFound = (c.Info.InstrAddr == matchAddr)
			}
		} else {
			// Standard: Stop if instruction is NOT linear flow (i.e. is a Waypoint)
			if c.Info.Type != common.InstrTypeOther {
				bWPFound = true
			}
		}

		if !bWPFound {
			// Advance to next instruction
			c.Info.InstrAddr = c.EnRangeAddr
			// Assume implicit ISA (linear flow) remains constant
			c.Info.ISA = c.Info.NextISA
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
