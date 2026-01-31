package common

// InstrType represents the type of instruction decoded from memory
type InstrType int

const (
	// InstrTypeUnknown indicates an unrecognized instruction
	InstrTypeUnknown InstrType = iota

	// InstrTypeBranch indicates a conditional or unconditional branch
	InstrTypeBranch

	// InstrTypeBranchIndirect indicates an indirect branch (register-based)
	InstrTypeBranchIndirect

	// InstrTypeNormal indicates a non-branch instruction
	InstrTypeNormal
)

func (t InstrType) String() string {
	switch t {
	case InstrTypeUnknown:
		return "Unknown"
	case InstrTypeBranch:
		return "Branch"
	case InstrTypeBranchIndirect:
		return "BranchIndirect"
	case InstrTypeNormal:
		return "Normal"
	default:
		return "Invalid"
	}
}

// InstrInfo contains decoded information about an instruction
type InstrInfo struct {
	// Type of instruction (branch, normal, etc.)
	Type InstrType

	// Size in bytes (2 for Thumb, 4 for ARM/Thumb2)
	Size uint32

	// IsBranch indicates if this is any kind of branch instruction
	IsBranch bool

	// IsConditional indicates if the branch is conditional
	IsConditional bool

	// IsLink indicates if this is a branch with link (BL/BLX)
	IsLink bool

	// BranchTarget is the calculated branch target address (for direct branches)
	BranchTarget uint64

	// HasBranchTarget indicates if BranchTarget is valid
	HasBranchTarget bool

	// IsReturn indicates an indirect branch that returns (e.g., BX LR)
	IsReturn bool

	// Opcode is the raw instruction bytes
	Opcode uint32
}

// NewInstrInfo creates a new InstrInfo with default values
func NewInstrInfo() *InstrInfo {
	return &InstrInfo{
		Type:            InstrTypeUnknown,
		Size:            4, // Default to ARM instruction size
		IsBranch:        false,
		IsConditional:   false,
		HasBranchTarget: false,
		IsReturn:        false,
	}
}
