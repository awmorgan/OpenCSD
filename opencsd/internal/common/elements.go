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
// It normalizes protocol-specific packets (PTM, ETM) into a standard format.
type TraceElement struct {
	ElemType   GenTrcElemType
	Context    PeContext
	Timestamp  uint64
	CycleCount uint32

	// Address Range fields
	StAddr uint64 // Start Address
	EnAddr uint64 // End Address
	ISA    Isa    // Instruction Set Architecture

	// Flags
	HasTS bool
	HasCC bool

	// Exception / Event Info
	ExcepID uint32
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

// ToString mimics the C++ OcsdTraceElement::toString() method.
// This is CRITICAL for parity testing against trc_pkt_lister output.
func (e *TraceElement) ToString() string {
	var sb strings.Builder

	// Helper to mimic C++ format: "Idx:<N>; <Description>"
	// Note: The index is usually printed by the lister loop, not the element itself.
	// We focus on the element content here.

	switch e.ElemType {
	case ElemTraceOn:
		sb.WriteString("Trace On")
	case ElemNoSync:
		sb.WriteString("No Sync")
	case ElemPeContext:
		fmt.Fprintf(&sb, "PE Context: %s", e.Context.String())
	case ElemInstrRange:
		fmt.Fprintf(&sb, "I_Range: 0x%X - 0x%X; %s", e.StAddr, e.EnAddr, e.ISA.String())
	case ElemTimestamp:
		fmt.Fprintf(&sb, "Timestamp: %d", e.Timestamp)
	case ElemCycleCount:
		fmt.Fprintf(&sb, "Cycle Count: %d", e.CycleCount)
	case ElemException:
		fmt.Fprintf(&sb, "Exception: ID 0x%X", e.ExcepID)
	case ElemExceptionRet:
		sb.WriteString("Exception Return")
	default:
		fmt.Fprintf(&sb, "Unknown Element: %d", e.ElemType)
	}

	return sb.String()
}

func (c PeContext) String() string {
	// Matches C++ ocsd_pe_context::toString
	// Example: "EL2; NS; VMID:0x0; CID:0x0"
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
