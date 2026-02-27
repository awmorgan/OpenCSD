package ptm

import (
	"fmt"
	"strings"

	"opencsd/internal/ocsd"
)

// PktType represents a PTM specific packet type.
type PktType int

const (
	// markers for unknown packets
	PktNotSync       PktType = iota // no sync found yet
	PktIncompleteEOT                // flushing incomplete packet at end of trace.
	PktNoError                      // no error base type packet.

	// markers for valid packets
	PktBranchAddress     // Branch address with optional exception.
	PktASync             // Alignment Synchronisation.
	PktISync             // Instruction sync with address.
	PktTrigger           // trigger packet
	PktWPointUpdate      // Waypoint update.
	PktIgnore            // ignore packet.
	PktContextID         // context id packet.
	PktVMID              // VMID packet
	PktAtom              // atom waypoint packet.
	PktTimestamp         // timestamp packet.
	PktExceptionRet      // exception return.
	PktBranchOrBypassEOT // interpreter FSM 'state'
	PktTPIUPadEOB        // pad end of a buffer

	// markers for bad packets
	PktBadSequence // invalid sequence for packet type
	PktReserved    // Reserved packet encoding
)

// Context represents the execution context state for PTM.
type Context struct {
	CurrAltISA bool
	CurrNS     bool
	CurrHyp    bool
	Updated    bool
	UpdatedC   bool
	UpdatedV   bool

	CtxtID uint32
	VMID   uint8
}

// Excep represents an exception inside a PTM packet.
type Excep struct {
	Type    ocsd.ArmV7Exception
	Number  uint16
	Present bool
}

// Packet represents a parsed PTM packet element.
type Packet struct {
	Type    PktType
	ErrType PktType

	CurrISA ocsd.ISA
	PrevISA ocsd.ISA

	AddrBits  int
	AddrValid int
	AddrVal   ocsd.VAddr

	Context Context
	Atom    ocsd.PktAtom

	ISyncReason ocsd.ISyncReason

	CycleCount uint32
	CCValid    bool

	Timestamp    uint64
	TSUpdateBits uint8

	Exception Excep
}

func (p *Packet) Clear() {
	p.ErrType = PktNoError
	p.CycleCount = 0
	p.CCValid = false
	p.Context.Updated = false
	p.Context.UpdatedC = false
	p.Context.UpdatedV = false
	p.TSUpdateBits = 0
	p.Atom.EnBits = 0
	p.Exception.Present = false
	p.PrevISA = p.CurrISA // mark ISA as not changed
}

func (p *Packet) ResetState() {
	p.Type = PktNotSync

	p.Context.CtxtID = 0
	p.Context.VMID = 0
	p.Context.CurrAltISA = false
	p.Context.CurrHyp = false
	p.Context.CurrNS = false

	p.AddrValid = 0
	p.AddrVal = 0

	p.PrevISA = ocsd.ISAUnknown
	p.CurrISA = ocsd.ISAUnknown

	p.Timestamp = 0

	p.Clear()
}

func (p *Packet) UpdateAddress(partAddrVal ocsd.VAddr, updateBits int) {
	validMask := (ocsd.VAddr(1) << updateBits) - 1
	p.AddrBits = updateBits
	p.AddrVal &^= validMask
	p.AddrVal |= (partAddrVal & validMask)
	if updateBits > p.AddrValid {
		p.AddrValid = updateBits
	}
}

func (p *Packet) UpdateTimestamp(tsVal uint64, updateBits uint8) {
	validMask := (uint64(1) << updateBits) - 1
	p.Timestamp &^= validMask
	p.Timestamp |= (tsVal & validMask)
	p.TSUpdateBits = updateBits
}

func (p *Packet) SetCycleAccAtomFromPHdr(pHdr uint8) {
	p.Atom.Num = 1
	if (pHdr & 0x2) != 0 {
		p.Atom.EnBits = 0x0
	} else {
		p.Atom.EnBits = 0x1
	}
}

func (p *Packet) SetAtomFromPHdr(pHdr uint8) {
	atomFmtID := pHdr & 0xF0
	if atomFmtID == 0x80 {
		if (pHdr & 0x08) == 0x08 {
			p.Atom.Num = 2
		} else {
			p.Atom.Num = 1
		}
	} else if atomFmtID == 0x90 {
		p.Atom.Num = 3
	} else {
		if (pHdr & 0xE0) == 0xA0 {
			p.Atom.Num = 4
		} else {
			p.Atom.Num = 5
		}
	}

	atomMask := uint8(0x2)
	p.Atom.EnBits = 0
	for i := 0; i < int(p.Atom.Num); i++ {
		p.Atom.EnBits <<= 1
		if (atomMask & pHdr) == 0 {
			p.Atom.EnBits |= 0x1
		}
		atomMask <<= 1
	}
}

func (p *Packet) IsBadPacket() bool {
	return p.Type >= PktBadSequence
}

func (p *Packet) String() string {
	name, desc := packetTypeName(p.Type)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s : %s; ", name, desc))

	switch p.Type {
	case PktBadSequence:
		errName, _ := packetTypeName(p.ErrType)
		sb.WriteString(fmt.Sprintf("[%s]; ", errName))
	case PktAtom:
		sb.WriteString(p.getAtomStr())
	case PktContextID:
		sb.WriteString(fmt.Sprintf("CtxtID=0x%08x; ", p.Context.CtxtID))
	case PktVMID:
		sb.WriteString(fmt.Sprintf("VMID=0x%02x; ", p.Context.VMID))
	case PktWPointUpdate, PktBranchAddress:
		sb.WriteString(p.getBranchAddressStr())
	case PktISync:
		sb.WriteString(p.getISyncStr())
	case PktTimestamp:
		sb.WriteString(p.getTSStr())
	}
	return sb.String()
}

func (p *Packet) ToStringFmt(fmtFlags uint32) string {
	return p.String()
}

func (p *Packet) getAtomStr() string {
	var sb strings.Builder
	bitpattern := p.Atom.EnBits

	if p.CCValid {
		if (bitpattern & 0x1) != 0 {
			sb.WriteString("E; ")
		} else {
			sb.WriteString("N; ")
		}
		sb.WriteString(p.getCycleCountStr())
	} else {
		for i := 0; i < int(p.Atom.Num); i++ {
			if (bitpattern & 0x1) != 0 {
				sb.WriteString("E")
			} else {
				sb.WriteString("N")
			}
			bitpattern >>= 1
		}
		sb.WriteString("; ")
	}
	return sb.String()
}

func (p *Packet) getBranchAddressStr() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Addr=0x%x; ", p.AddrVal)) // simplified for now

	if p.CurrISA != p.PrevISA {
		sb.WriteString(p.getISAStr())
	}

	if p.Context.Updated {
		if p.Context.CurrNS {
			sb.WriteString("NS; ")
		} else {
			sb.WriteString("S; ")
		}
		if p.Context.CurrHyp {
			sb.WriteString("Hyp; ")
		}
	}

	if p.Exception.Present {
		sb.WriteString(p.getExcepStr())
	}

	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}

	return sb.String()
}

func (p *Packet) getISAStr() string {
	switch p.CurrISA {
	case ocsd.ISAArm:
		return "ISA=ARM(32); "
	case ocsd.ISAThumb2:
		return "ISA=Thumb2; "
	case ocsd.ISAAArch64:
		return "ISA=AArch64; "
	case ocsd.ISATee:
		return "ISA=ThumbEE; "
	case ocsd.ISAJazelle:
		return "ISA=Jazelle; "
	default:
		return "ISA=Unknown; "
	}
}

func (p *Packet) getExcepStr() string {
	excepNames := []string{
		"No Exception", "Debug Halt", "SMC", "Hyp",
		"Async Data Abort", "Jazelle", "Reserved", "Reserved",
		"PE Reset", "Undefined Instr", "SVC", "Prefetch Abort",
		"Data Fault", "Generic", "IRQ", "FIQ",
	}

	name := "Unknown"
	if p.Exception.Number < 16 {
		name = excepNames[p.Exception.Number]
	}
	return fmt.Sprintf("Excep=%s [%02x]; ", name, p.Exception.Number)
}

func (p *Packet) getISyncStr() string {
	reasons := []string{"Periodic", "Trace Enable", "Restart Overflow", "Debug Exit"}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("(%s); ", reasons[int(p.ISyncReason)]))
	sb.WriteString(fmt.Sprintf("Addr=0x%08x; ", uint32(p.AddrVal)))

	if p.Context.CurrNS {
		sb.WriteString("NS; ")
	} else {
		sb.WriteString("S; ")
	}

	if p.Context.CurrHyp {
		sb.WriteString("Hyp; ")
	} else {
		sb.WriteString(" ")
	}

	if p.Context.UpdatedC {
		sb.WriteString(fmt.Sprintf("CtxtID=%08x; ", p.Context.CtxtID))
	}

	sb.WriteString(p.getISAStr())

	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}

	return sb.String()
}

func (p *Packet) getTSStr() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("TS=0x%x(%d); ", p.Timestamp, p.Timestamp))
	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}
	return sb.String()
}

func (p *Packet) getCycleCountStr() string {
	return fmt.Sprintf("Cycles=%d; ", p.CycleCount)
}

func packetTypeName(t PktType) (string, string) {
	switch t {
	case PktNotSync:
		return "NOTSYNC", "PTM Not Synchronised"
	case PktIncompleteEOT:
		return "INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"
	case PktNoError:
		return "NO_ERROR", "Error type not set"
	case PktBadSequence:
		return "BAD_SEQUENCE", "Invalid sequence in packet"
	case PktReserved:
		return "RESERVED", "Reserved Packet Header"
	case PktBranchAddress:
		return "BRANCH_ADDRESS", "Branch address packet"
	case PktASync:
		return "ASYNC", "Alignment Synchronisation Packet"
	case PktISync:
		return "ISYNC", "Instruction Synchronisation packet"
	case PktTrigger:
		return "TRIGGER", "Trigger Event packet"
	case PktWPointUpdate:
		return "WP_UPDATE", "Waypoint update packet"
	case PktIgnore:
		return "IGNORE", "Ignore packet"
	case PktContextID:
		return "CTXTID", "Context ID packet"
	case PktVMID:
		return "VMID", "VM ID packet"
	case PktAtom:
		return "ATOM", "Atom packet"
	case PktTimestamp:
		return "TIMESTAMP", "Timestamp packet"
	case PktExceptionRet:
		return "ERET", "Exception return packet"
	default:
		return "UNKNOWN", "Unknown packet type"
	}
}
