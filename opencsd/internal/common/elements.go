package common

import (
	"fmt"
	"strings"
)

// GenTrcElemType maps to ocsd_gen_trc_elem_t
type GenTrcElemType int

const (
	ElemUnknown      GenTrcElemType = 0
	ElemNoSync       GenTrcElemType = 1
	ElemTraceOn      GenTrcElemType = 2
	ElemEOTrace      GenTrcElemType = 3
	ElemPeContext    GenTrcElemType = 4
	ElemInstrRange   GenTrcElemType = 5
	ElemAddrNacc     GenTrcElemType = 7
	ElemException    GenTrcElemType = 9
	ElemExceptionRet GenTrcElemType = 10
	ElemTimestamp    GenTrcElemType = 11
	ElemCycleCount   GenTrcElemType = 12
	ElemEvent        GenTrcElemType = 13
	ElemSwTrace      GenTrcElemType = 14
	ElemSyncMarker   GenTrcElemType = 15
	ElemMemTrans     GenTrcElemType = 16
	ElemCustom       GenTrcElemType = 19
)

// TraceElement represents the OcsdTraceElement C++ class.
type TraceElement struct {
	ElemType   GenTrcElemType
	Context    PeContext
	Timestamp  uint64
	CycleCount uint32

	// Address Range fields
	StAddr uint64 // Start Address
	EnAddr uint64 // End Address
	ISA    Isa    // Instruction Set Architecture

	// Instruction-range specific fields
	NumInstr      int       // num_i in C++ output
	LastInstr     InstrInfo // detailed info for last instruction in range
	LastInstrExec bool      // was the last instruction executed (E/N)

	// Flags
	HasTS bool
	HasCC bool

	// Exception / Event Info
	ExcepID      uint32
	ExcepRetAddr bool // Flag: is the EnAddr a valid preferred return address?

	// TraceOn reason
	TraceOnReason int
}

// PeContext represents ocsd_pe_context
type PeContext struct {
	SecurityLevel  SecurityLevel // S, NS, Root
	ExceptionLevel EL            // EL0, EL1, EL2, EL3
	VMID           uint32
	ContextID      uint32
}

type SecurityLevel int

const (
	SecSecure    SecurityLevel = 0
	SecNonSecure SecurityLevel = 1
	SecRoot      SecurityLevel = 2
)

type EL int

const (
	EL0 EL = 0
	EL1 EL = 1
	EL2 EL = 2
	EL3 EL = 3
)

type Isa int

const (
	IsaArm32   Isa = 0
	IsaThumb   Isa = 1
	IsaA64     Isa = 2
	IsaTEE     Isa = 3 // ThumbEE
	IsaJazelle Isa = 4
)

type AtomVal int

const (
	AtomN AtomVal = 0
	AtomE AtomVal = 1
)

// Instruction Types
const (
	InstrTypeOther    = 0
	InstrTypeBranch   = 1
	InstrTypeIndirect = 2
	InstrTypeISB      = 3 // Barrier
	InstrTypeDSB_DMB  = 4 // Barrier
	InstrTypeWFI_WFE  = 5 // Wait
)

// Instruction SubTypes
const (
	InstrSubTypeNone         = 0
	InstrSubTypeBrLink       = 1
	InstrSubTypeV7ImpliedRet = 2
	InstrSubTypeV8Ret        = 3
	InstrSubTypeV8Eret       = 4
)

// InstrInfo mimics ocsd_instr_info
type InstrInfo struct {
	InstrAddr     uint64
	Opcode        uint32
	InstrSize     uint8
	ISA           Isa
	NextISA       Isa
	Type          int
	SubType       int
	IsConditional bool
	IsLink        bool
	BranchAddr    uint64
}

// ToString mimics the C++ OcsdTraceElement::toString() method.
func (e *TraceElement) ToString() string {
	isaStr := func(isa Isa) string {
		switch isa {
		case IsaArm32:
			return "A32"
		case IsaThumb:
			return "T32"
		case IsaA64:
			return "A64"
		default:
			return "Unk"
		}
	}

	instrType := []string{"--- ", "BR  ", "iBR ", "ISB ", "DSB.DMB", "WFI.WFE", "TSTART"}
	instrSub := []string{"--- ", "b+link ", "V7:impl ret", "A64:ret", "A64:eret"}
	traceOnReason := []string{"begin or filter", "overflow", "debug restart"}

	var sb strings.Builder

	switch e.ElemType {
	case ElemNoSync:
		sb.WriteString("OCSD_GEN_TRC_ELEM_NO_SYNC( [init-decoder])")

	case ElemTraceOn:
		reason := "begin or filter"
		if e.TraceOnReason >= 0 && e.TraceOnReason < len(traceOnReason) {
			reason = traceOnReason[e.TraceOnReason]
		}
		fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_TRACE_ON( [%s])", reason)

	case ElemEOTrace:
		sb.WriteString("OCSD_GEN_TRC_ELEM_EO_TRACE( [end-of-trace])")

	case ElemPeContext:
		isaS := isaStr(e.ISA)
		sec := "S"
		if e.Context.SecurityLevel == SecNonSecure {
			sec = "NS"
		}
		bits := "32-bit; "
		if e.ISA == IsaA64 {
			bits = "64-bit; "
		}
		fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_PE_CONTEXT((ISA=%s) %s; %s", isaS, sec, bits)
		if e.Context.VMID != 0 {
			fmt.Fprintf(&sb, "VMID=0x%x; ", e.Context.VMID)
		}
		if e.Context.ContextID != 0 {
			fmt.Fprintf(&sb, "CTXTID=0x%x; ", e.Context.ContextID)
		}
		sb.WriteString(")")

	case ElemInstrRange:
		num := e.NumInstr
		if num == 0 {
			num = 1
		}
		lastSz := int(e.LastInstr.InstrSize)
		fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_INSTR_RANGE(exec range=0x%x:[0x%x] num_i(%d) last_sz(%d) (ISA=%s) ", e.StAddr, e.EnAddr, num, lastSz, isaStr(e.ISA))

		if e.LastInstrExec {
			sb.WriteString("E ")
		} else {
			sb.WriteString("N ")
		}

		typeIdx := int(e.LastInstr.Type)
		if typeIdx >= 0 && typeIdx < len(instrType) {
			sb.WriteString(instrType[typeIdx])
		}

		subIdx := int(e.LastInstr.SubType)
		if subIdx > 0 && subIdx < len(instrSub) {
			sb.WriteString(instrSub[subIdx])
		}

		if e.LastInstr.IsConditional {
			sb.WriteString(" <cond>")
		}

		if e.HasCC {
			fmt.Fprintf(&sb, " [CC=%d]; ", e.CycleCount)
		}

		sb.WriteString(")")

	case ElemAddrNacc:
		fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_ADDR_NACC(addr=0x%x)", e.StAddr)

	case ElemException:
		if e.ExcepRetAddr {
			fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_EXCEPTION(pref ret addr:0x%x; ", e.EnAddr)
		} else {
			sb.WriteString("OCSD_GEN_TRC_ELEM_EXCEPTION(")
		}
		fmt.Fprintf(&sb, "excep num (0x%02x) )", e.ExcepID)

	case ElemTimestamp:
		fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_TIMESTAMP( [ TS=0x%x]; )", e.Timestamp)

	case ElemCycleCount:
		fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_CYCLE_COUNT( [CC=%d]; )", e.CycleCount)

	case ElemExceptionRet:
		sb.WriteString("OCSD_GEN_TRC_ELEM_EXCEPTION_RET()")

	default:
		fmt.Fprintf(&sb, "OCSD_GEN_TRC_ELEM_UNKNOWN(%d)", e.ElemType)
	}

	return sb.String()
}

func (c PeContext) String() string {
	secStr := "S"
	if c.SecurityLevel == SecNonSecure {
		secStr = "NS"
	}
	return fmt.Sprintf("EL%d; %s; VMID:0x%X; CID:0x%X", c.ExceptionLevel, secStr, c.VMID, c.ContextID)
}

func (i Isa) String() string {
	switch i {
	case IsaArm32:
		return "ARM"
	case IsaThumb:
		return "Thumb"
	case IsaA64:
		return "A64"
	default:
		return "Unknown"
	}
}
