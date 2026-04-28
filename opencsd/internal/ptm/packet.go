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
	Index ocsd.TrcIndex
	Type  PktType

	CurrISA ocsd.ISA
	PrevISA ocsd.ISA

	AddrBits      int
	AddrValid     bool
	AddrValidBits int
	AddrVal       ocsd.VAddr

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

	p.AddrBits = 0
	p.AddrValid = false
	p.AddrValidBits = 0
	p.AddrVal = 0

	p.PrevISA = ocsd.ISAUnknown
	p.CurrISA = ocsd.ISAUnknown

	p.Timestamp = 0

	p.Clear()
}

func (p *Packet) UpdateAddress(partAddrVal ocsd.VAddr, updateBits int) {
	validMask := ocsd.VAddr(maskBits64(updateBits))
	p.AddrBits = updateBits
	p.AddrVal &^= validMask
	p.AddrVal |= (partAddrVal & validMask)
	p.AddrValid = updateBits > 0
	if updateBits > p.AddrValidBits {
		p.AddrValidBits = updateBits
	}
}

func (p *Packet) UpdateContextID(ctxtID uint32) {
	p.Context.CtxtID = ctxtID
	p.Context.UpdatedC = true
}

func (p *Packet) UpdateVMID(vmid uint8) {
	p.Context.VMID = vmid
	p.Context.UpdatedV = true
}

func (p *Packet) UpdateISA(currISA ocsd.ISA) {
	p.PrevISA = p.CurrISA
	p.CurrISA = currISA
}

func (p *Packet) SetException(exType ocsd.ArmV7Exception, exNum uint16, currNS bool, currHyp bool) {
	p.Context.CurrNS = currNS
	p.Context.CurrHyp = currHyp
	p.Context.Updated = true
	p.Exception.Present = true
	p.Exception.Type = exType
	p.Exception.Number = exNum
}

func (p *Packet) UpdateTimestamp(tsVal uint64, updateBits uint8) {
	validMask := maskBits64(int(updateBits))
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
	switch atomFmtID {
	case 0x80:
		if (pHdr & 0x08) == 0x08 {
			p.Atom.Num = 2
		} else {
			p.Atom.Num = 1
		}
	case 0x90:
		p.Atom.Num = 3
	default:
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
	switch p.Type {
	case PktIncompleteEOT, PktBadSequence, PktReserved:
		return true
	default:
		return false
	}
}

func (p *Packet) String() string {
	info := packetInfo(p.Type)
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s : %s; ", info.name, info.desc)
	p.writeDetails(&sb)
	return sb.String()
}

func (p *Packet) writeDetails(sb *strings.Builder) {
	switch p.Type {
	case PktBadSequence:
		fmt.Fprintf(sb, "[%s]; ", PktTypeName(p.Type))
	case PktAtom:
		sb.WriteString(p.getAtomStr())
	case PktContextID:
		fmt.Fprintf(sb, "CtxtID=0x%08x; ", p.Context.CtxtID)
	case PktVMID:
		fmt.Fprintf(sb, "VMID=0x%02x; ", p.Context.VMID)
	case PktWPointUpdate, PktBranchAddress:
		sb.WriteString(p.getBranchAddressStr())
	case PktISync:
		sb.WriteString(p.getISyncStr())
	case PktTimestamp:
		sb.WriteString(p.getTSStr())
	}
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
	sb.WriteString("Addr=")
	sb.WriteString(formatTraceValueHex(32, p.AddrValidBits, uint64(p.AddrVal), p.AddrBits))
	sb.WriteString("; ")

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

var ptmExceptionNames = [...]string{
	"No Exception", "Debug Halt", "SMC", "Hyp",
	"Async Data Abort", "Jazelle", "Reserved", "Reserved",
	"PE Reset", "Undefined Instr", "SVC", "Prefetch Abort",
	"Data Fault", "Generic", "IRQ", "FIQ",
}

var iSyncReasonNames = [...]string{"Periodic", "Trace Enable", "Restart Overflow", "Debug Exit"}

func (p *Packet) getExcepStr() string {
	name := "Unknown"
	if int(p.Exception.Number) < len(ptmExceptionNames) {
		name = ptmExceptionNames[p.Exception.Number]
	}
	return fmt.Sprintf("Excep=%s [%02x]; ", name, p.Exception.Number)
}

func (p *Packet) getISyncStr() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "(%s); ", iSyncReasonName(p.ISyncReason))
	fmt.Fprintf(&sb, "Addr=0x%08x; ", uint32(p.AddrVal))

	if p.Context.CurrNS {
		sb.WriteString("NS; ")
	} else {
		sb.WriteString("S; ")
	}

	if p.Context.CurrHyp {
		sb.WriteString("Hyp; ")
	}

	if p.Context.UpdatedC {
		fmt.Fprintf(&sb, "CtxtID=0x%08x; ", p.Context.CtxtID)
	}

	sb.WriteString(" ")
	sb.WriteString(p.getISAStr())

	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}

	return sb.String()
}

func (p *Packet) getTSStr() string {
	var sb strings.Builder
	sb.WriteString("TS=")
	sb.WriteString(formatTraceValueHex(64, 64, p.Timestamp, int(p.TSUpdateBits)))
	fmt.Fprintf(&sb, "(%d); ", p.Timestamp)
	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}
	return sb.String()
}

func (p *Packet) getCycleCountStr() string {
	return fmt.Sprintf("Cycles=%d; ", p.CycleCount)
}

type pktTypeInfo struct {
	name string
	desc string
}

var packetTypeInfos = map[PktType]pktTypeInfo{
	PktNotSync:       {"NOTSYNC", "PTM Not Synchronised"},
	PktIncompleteEOT: {"INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"},
	PktBadSequence:   {"BAD_SEQUENCE", "Invalid sequence in packet"},
	PktReserved:      {"RESERVED", "Reserved Packet Header"},
	PktBranchAddress: {"BRANCH_ADDRESS", "Branch address packet"},
	PktASync:         {"ASYNC", "Alignment Synchronisation Packet"},
	PktISync:         {"ISYNC", "Instruction Synchronisation packet"},
	PktTrigger:       {"TRIGGER", "Trigger Event packet"},
	PktWPointUpdate:  {"WP_UPDATE", "Waypoint update packet"},
	PktIgnore:        {"IGNORE", "Ignore packet"},
	PktContextID:     {"CTXTID", "Context ID packet"},
	PktVMID:          {"VMID", "VM ID packet"},
	PktAtom:          {"ATOM", "Atom packet"},
	PktTimestamp:     {"TIMESTAMP", "Timestamp packet"},
	PktExceptionRet:  {"ERET", "Exception return packet"},
}

func packetInfo(t PktType) pktTypeInfo {
	if info, ok := packetTypeInfos[t]; ok {
		return info
	}
	return pktTypeInfo{"UNKNOWN", "Unknown packet type"}
}

// PktTypeName returns the canonical packet-type name used in raw/golden output.
func PktTypeName(t PktType) string {
	return packetInfo(t).name
}

func iSyncReasonName(reason ocsd.ISyncReason) string {
	idx := int(reason)
	if idx >= 0 && idx < len(iSyncReasonNames) {
		return iSyncReasonNames[idx]
	}
	return "Unknown"
}

func maskBits64(bits int) uint64 {
	if bits <= 0 {
		return 0
	}
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}

func formatTraceValueHex(totalBits int, validBits int, value uint64, updateBits int) string {
	if totalBits < 4 {
		totalBits = 4
	}
	if totalBits > 64 {
		totalBits = 64
	}
	if validBits < 0 {
		validBits = 0
	}
	if validBits > totalBits {
		validBits = totalBits
	}

	numHexChars := (totalBits + 3) / 4
	validChars := 0
	if validBits > 0 {
		validChars = (validBits + 3) / 4
	}

	var sb strings.Builder
	sb.WriteString("0x")
	for i := validChars; i < numHexChars; i++ {
		sb.WriteByte('?')
	}
	if validChars > 0 {
		fmt.Fprintf(&sb, "%0*X", validChars, value&maskBits64(validBits))
	}
	if validBits < totalBits {
		fmt.Fprintf(&sb, " (%d:0)", validBits-1)
	}
	if updateBits > 0 {
		fmt.Fprintf(&sb, " ~[0x%X]", value&maskBits64(updateBits))
	}
	return sb.String()
}
