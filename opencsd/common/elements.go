package common

import "fmt"

// ElemType represents the type of generic trace element
type ElemType int

const (
	ElemTypeUnknown         ElemType = iota
	ElemTypePeContext                // Processing Element context (ISA, security state, etc.)
	ElemTypeAddrRange                // Instruction address range
	ElemTypeAddrNacc                 // Address not accessible (memory read failed)
	ElemTypeException                // Exception event
	ElemTypeExceptionReturn          // Exception return event
	ElemTypeTimestamp                // Timestamp value
	ElemTypeNoSync                   // No synchronization
	ElemTypeTraceOn                  // Trace restarted/enabled
	ElemTypeEOTrace                  // End of trace
)

func (t ElemType) String() string {
	switch t {
	case ElemTypePeContext:
		return "PE_CONTEXT"
	case ElemTypeAddrRange:
		return "ADDR_RANGE"
	case ElemTypeAddrNacc:
		return "ADDR_NACC"
	case ElemTypeException:
		return "EXCEPTION"
	case ElemTypeExceptionReturn:
		return "EXCEPTION_RETURN"
	case ElemTypeTimestamp:
		return "TIMESTAMP"
	case ElemTypeNoSync:
		return "NO_SYNC"
	case ElemTypeTraceOn:
		return "TRACE_ON"
	case ElemTypeEOTrace:
		return "EO_TRACE"
	default:
		return "UNKNOWN"
	}
}

// ISA represents instruction set architecture
type ISA int

const (
	ISAARM ISA = iota
	ISAThumb2
	ISATEE
	ISAThumb
	ISAA64
)

func (i ISA) String() string {
	switch i {
	case ISAARM:
		return "ARM(32)"
	case ISAThumb2:
		return "Thumb2"
	case ISAThumb:
		return "Thumb"
	case ISATEE:
		return "TEE"
	case ISAA64:
		return "AArch64"
	default:
		return "Unknown"
	}
}

// SecurityState represents security state
type SecurityState int

const (
	SecurityStateSecure SecurityState = iota
	SecurityStateNonSecure
)

func (s SecurityState) String() string {
	switch s {
	case SecurityStateSecure:
		return "S"
	case SecurityStateNonSecure:
		return "N"
	default:
		return "Unknown"
	}
}

// ExceptionLevel represents exception level (EL0-EL3)
type ExceptionLevel int

const (
	EL0 ExceptionLevel = iota
	EL1
	EL2
	EL3
)

func (e ExceptionLevel) String() string {
	return fmt.Sprintf("EL%d", int(e))
}

// PEContext represents Processing Element context information
type PEContext struct {
	ContextID      uint32         // Context ID
	VMID           uint32         // Virtual Machine ID
	ISA            ISA            // Current instruction set
	SecurityState  SecurityState  // Secure/Non-secure
	ExceptionLevel ExceptionLevel // Exception level (ARMv8)
	Bits64         bool           // 64-bit mode (ARMv8)
}

// AddrRange represents an executed instruction address range
type AddrRange struct {
	StartAddr   uint64 // Start address
	EndAddr     uint64 // End address (exclusive)
	ISA         ISA    // ISA for this range
	NumInstr    uint32 // Number of instructions executed
	LastInstrSz uint8  // Size of last instruction in bytes
	// Last instruction metadata (for output formatting)
	LastInstrExec   bool      // Last instruction executed (E/N)
	LastInstrType   InstrType // Last instruction type (branch/indirect/normal)
	LastInstrCond   bool      // Last instruction is conditional
	LastInstrLink   bool      // Last instruction is a link (BL/BLX)
	LastInstrReturn bool      // Last instruction is an indirect return (e.g., BX LR)
}

// ExceptionInfo represents exception information
type ExceptionInfo struct {
	Number       uint16 // Exception number
	Type         string // Exception type description
	PrefRetAddr  uint64 // Preferred return address
	ResumeAddr   uint64 // Resume address after exception
	FaultAddr    uint64 // Fault address (if applicable)
	FaultPending bool   // Fault is pending
}

// GenericTraceElement represents a decoded trace element
// This is the output of the packet decoder - a semantic representation
// of what happened in the trace
type GenericTraceElement struct {
	Type ElemType

	// PE Context information (for ElemTypePeContext)
	Context PEContext

	// Address range information (for ElemTypeAddrRange)
	AddrRange AddrRange

	// Address not accessible info (for ElemTypeAddrNacc)
	NaccAddr     uint64        // Address that could not be read
	NaccMemSpace SecurityState // Memory space (secure/non-secure)

	// Exception information (for ElemTypeException)
	Exception ExceptionInfo

	// Timestamp value (for ElemTypeTimestamp)
	Timestamp uint64

	// Trace context
	TraceOnReason string // Reason for trace restart (for ElemTypeTraceOn)
}

// NewGenericTraceElement creates a new trace element of the specified type
func NewGenericTraceElement(elemType ElemType) *GenericTraceElement {
	return &GenericTraceElement{
		Type: elemType,
	}
}

// Description returns a human-readable description of the element
func (e *GenericTraceElement) Description() string {
	switch e.Type {
	case ElemTypePeContext:
		return fmt.Sprintf("PE_CONTEXT: ISA=%s %s EL=%s CTXTID=0x%08x VMID=0x%x",
			e.Context.ISA,
			e.Context.SecurityState,
			e.Context.ExceptionLevel,
			e.Context.ContextID,
			e.Context.VMID)

	case ElemTypeAddrRange:
		return fmt.Sprintf("ADDR_RANGE: [0x%x - 0x%x] ISA=%s NumInstr=%d",
			e.AddrRange.StartAddr,
			e.AddrRange.EndAddr,
			e.AddrRange.ISA,
			e.AddrRange.NumInstr)

	case ElemTypeAddrNacc:
		return fmt.Sprintf("ADDR_NACC: 0x%x %s", e.NaccAddr, e.NaccMemSpace)

	case ElemTypeException:
		return fmt.Sprintf("EXCEPTION: num=0x%x type=%s retAddr=0x%x",
			e.Exception.Number,
			e.Exception.Type,
			e.Exception.PrefRetAddr)

	case ElemTypeExceptionReturn:
		return "EXCEPTION_RETURN"

	case ElemTypeTimestamp:
		return fmt.Sprintf("TIMESTAMP: 0x%x", e.Timestamp)

	case ElemTypeNoSync:
		return "NO_SYNC"

	case ElemTypeTraceOn:
		if e.TraceOnReason != "" {
			return fmt.Sprintf("TRACE_ON: %s", e.TraceOnReason)
		}
		return "TRACE_ON"

	case ElemTypeEOTrace:
		return "END_OF_TRACE"

	default:
		return "UNKNOWN_ELEMENT"
	}
}
