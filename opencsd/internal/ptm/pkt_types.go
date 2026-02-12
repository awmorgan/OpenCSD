package ptm

import (
	"fmt"
	"strings"

	"opencsd/internal/common"
)

// PtmPktType maps to ocsd_ptm_pkt_type.
type PtmPktType int

const (
	ptmPktNotSync PtmPktType = iota
	ptmPktIncompleteEOT
	ptmPktNoError
	ptmPktBranchAddress
	ptmPktAsync
	ptmPktISync
	ptmPktTrigger
	ptmPktWPUpdate
	ptmPktIgnore
	ptmPktContextID
	ptmPktVMID
	ptmPktAtom
	ptmPktTimestamp
	ptmPktExceptionRet
	ptmPktBranchOrBypassEOT
	ptmPktTpiuPadEOB
	ptmPktBadSequence
	ptmPktReserved
)

type pktType = PtmPktType

type isa = common.Isa

const (
	isaARM     isa = common.IsaArm32
	isaThumb2  isa = common.IsaThumb
	isaAArch64 isa = common.IsaA64
	isaTEE     isa = common.IsaTEE
	isaJazelle isa = common.IsaJazelle
	isaUnknown isa = -1
)

type iSyncReason int

const (
	iSyncPeriodic iSyncReason = iota
	iSyncTraceEnable
	iSyncRestartOverflow
	iSyncDebugExit
)

type ptmException struct {
	present bool
	typeID  int
	number  uint16
}

type ptmContext struct {
	currAltISA bool
	currNS     bool
	currHyp    bool
	updated    bool
	updatedC   bool
	updatedV   bool
	ctxtID     uint32
	vmid       uint8
}

type ptmAddr struct {
	val       uint32
	pktBits   uint8
	validBits uint8
}

type ptmAtom struct {
	enBits uint32
	num    uint8
}

// PtmPacket represents a single decoded PTM protocol packet.
// It holds the raw data extracted from the byte stream before it is
// converted into a generic trace element.
type PtmPacket struct {
	typeID     pktType
	errType    pktType
	currISA    isa
	prevISA    isa
	addr       ptmAddr
	context    ptmContext
	atom       ptmAtom
	iSync      iSyncReason
	cycleCount uint32
	ccValid    bool
	timestamp  uint64
	tsUpdate   uint8
	exception  ptmException

	Index    int
	RawBytes []byte
}

type ptmPacket = PtmPacket

func (p *PtmPacket) resetState() {
	p.typeID = ptmPktNotSync
	p.context = ptmContext{}
	p.addr = ptmAddr{}
	p.currISA = isaUnknown
	p.prevISA = isaUnknown
	p.timestamp = 0
	p.clear()
}

func (p *PtmPacket) clear() {
	p.errType = ptmPktNoError
	p.cycleCount = 0
	p.ccValid = false
	p.context.updated = false
	p.context.updatedC = false
	p.context.updatedV = false
	p.tsUpdate = 0
	p.atom.enBits = 0
	p.exception.present = false
	p.prevISA = p.currISA
}

func (p *PtmPacket) setType(t pktType) { p.typeID = t }

func (p *PtmPacket) setErrType(t pktType) {
	p.errType = p.typeID
	p.typeID = t
}

func (p *PtmPacket) updateNS(ns int) {
	p.context.currNS = ns != 0
	p.context.updated = true
}

func (p *PtmPacket) updateAltISA(alt int) {
	p.context.currAltISA = alt != 0
	p.context.updated = true
}

func (p *PtmPacket) updateHyp(hyp int) {
	p.context.currHyp = hyp != 0
	p.context.updated = true
}

func (p *PtmPacket) updateISA(next isa) {
	p.prevISA = p.currISA
	p.currISA = next
}

func (p *PtmPacket) updateContextID(id uint32) {
	p.context.ctxtID = id
	p.context.updatedC = true
}

func (p *PtmPacket) updateVMID(id uint8) {
	p.context.vmid = id
	p.context.updatedV = true
}

func (p *PtmPacket) setException(typeID int, number uint16) {
	p.exception.present = true
	p.exception.typeID = typeID
	p.exception.number = number
}

func (p *PtmPacket) setISyncReason(reason iSyncReason) { p.iSync = reason }

func (p *PtmPacket) setCycleCount(val uint32) {
	p.cycleCount = val
	p.ccValid = true
}

func (p *PtmPacket) updateAddress(part uint32, updateBits int) {
	validMask := uint32(vaMask >> (maxVAValidBits - updateBits))
	p.addr.pktBits = uint8(updateBits)
	p.addr.val &^= validMask
	p.addr.val |= part & validMask
	if updateBits > int(p.addr.validBits) {
		p.addr.validBits = uint8(updateBits)
	}
}

func (p *PtmPacket) updateTimestamp(ts uint64, updateBits uint8) {
	validMask := ^uint64(0) >> (64 - updateBits)
	p.timestamp &^= validMask
	p.timestamp |= ts & validMask
	p.tsUpdate = updateBits
}

func (p *PtmPacket) setAtomFromPHdr(pHdr byte) {
	atomFmtID := pHdr & 0xF0
	if atomFmtID == 0x80 {
		if (pHdr & 0x08) == 0x08 {
			p.atom.num = 2
		} else {
			p.atom.num = 1
		}
	} else if atomFmtID == 0x90 {
		p.atom.num = 3
	} else {
		if (pHdr & 0xE0) == 0xA0 {
			p.atom.num = 4
		} else {
			p.atom.num = 5
		}
	}

	atomMask := byte(0x2)
	p.atom.enBits = 0
	for i := 0; i < int(p.atom.num); i++ {
		p.atom.enBits <<= 1
		if (atomMask & pHdr) == 0 {
			p.atom.enBits |= 0x1
		}
		atomMask <<= 1
	}
}

func (p *PtmPacket) setCycleAccAtomFromPHdr(pHdr byte) {
	p.atom.num = 1
	if (pHdr & 0x2) != 0 {
		p.atom.enBits = 0x0
	} else {
		p.atom.enBits = 0x1
	}
}

// ToString mimics the C++ packet lister output.
func (p *PtmPacket) ToString() string {
	name, desc := packetTypeName(p.typeID)
	var b strings.Builder
	b.WriteString(name)
	b.WriteString(" : ")
	b.WriteString(desc)
	b.WriteString("; ")

	switch p.typeID {
	case ptmPktBadSequence:
		name, _ = packetTypeName(p.errType)
		b.WriteString("[")
		b.WriteString(name)
		b.WriteString("]; ")
	case ptmPktAtom:
		b.WriteString(p.atomString())
	case ptmPktContextID:
		b.WriteString(fmt.Sprintf("CtxtID=0x%08X; ", p.context.ctxtID))
	case ptmPktVMID:
		b.WriteString(fmt.Sprintf("VMID=0x%02X; ", p.context.vmid))
	case ptmPktWPUpdate, ptmPktBranchAddress:
		b.WriteString(p.branchAddressString())
	case ptmPktISync:
		b.WriteString(p.iSyncString())
	case ptmPktTimestamp:
		b.WriteString(p.timestampString())
	}

	return b.String()
}

func (p *PtmPacket) toString() string {
	return p.ToString()
}

func (p *PtmPacket) atomString() string {
	var b strings.Builder
	bitpattern := p.atom.enBits
	if p.ccValid {
		if (bitpattern & 0x1) != 0 {
			b.WriteString("E")
		} else {
			b.WriteString("N")
		}
		b.WriteString("; ")
		b.WriteString(p.cycleCountString())
		return b.String()
	}

	for i := 0; i < int(p.atom.num); i++ {
		if (bitpattern & 0x1) != 0 {
			b.WriteString("E")
		} else {
			b.WriteString("N")
		}
		bitpattern >>= 1
	}
	b.WriteString("; ")
	return b.String()
}

func (p *PtmPacket) branchAddressString() string {
	var b strings.Builder
	addrStr := getValStr(32, int(p.addr.validBits), uint64(p.addr.val), true, int(p.addr.pktBits))
	b.WriteString("Addr=")
	b.WriteString(addrStr)
	b.WriteString("; ")

	if p.currISA != p.prevISA {
		b.WriteString(p.isaString())
	}

	if p.context.updated {
		if p.context.currNS {
			b.WriteString("NS; ")
		} else {
			b.WriteString("S; ")
		}
		if p.context.currHyp {
			b.WriteString("Hyp; ")
		}
	}

	if p.exception.present {
		b.WriteString(p.exceptionString())
	}

	if p.ccValid {
		b.WriteString(p.cycleCountString())
	}
	return b.String()
}

func (p *PtmPacket) exceptionString() string {
	excepNames := []string{
		"No Exception", "Debug Halt", "SMC", "Hyp",
		"Async Data Abort", "Jazelle", "Reserved", "Reserved",
		"PE Reset", "Undefined Instr", "SVC", "Prefetch Abort",
		"Data Fault", "Generic", "IRQ", "FIQ",
	}
	var name string
	if int(p.exception.number) < len(excepNames) {
		name = excepNames[p.exception.number]
	} else {
		name = "Unknown"
	}
	return fmt.Sprintf("Excep=%s [%02X]; ", name, p.exception.number)
}

func (p *PtmPacket) isaString() string {
	var isaStr string
	switch p.currISA {
	case isaARM:
		isaStr = "ARM(32)"
	case isaThumb2:
		isaStr = "Thumb2"
	case isaAArch64:
		isaStr = "AArch64"
	case isaTEE:
		isaStr = "ThumbEE"
	case isaJazelle:
		isaStr = "Jazelle"
	default:
		isaStr = "Unknown"
	}
	return fmt.Sprintf("ISA=%s; ", isaStr)
}

func (p *PtmPacket) iSyncString() string {
	reason := []string{"Periodic", "Trace Enable", "Restart Overflow", "Debug Exit"}
	var b strings.Builder
	b.WriteString("(")
	b.WriteString(reason[int(p.iSync)])
	b.WriteString("); ")
	b.WriteString(fmt.Sprintf("Addr=0x%08x; ", p.addr.val))
	if p.context.currNS {
		b.WriteString("NS; ")
	} else {
		b.WriteString("S; ")
	}
	if p.context.currHyp {
		b.WriteString("Hyp; ")
	} else {
		b.WriteString(" ")
	}
	if p.context.updatedC {
		b.WriteString(fmt.Sprintf("CtxtID=0x%08X; ", p.context.ctxtID))
	}
	b.WriteString(p.isaString())
	if p.ccValid {
		b.WriteString(p.cycleCountString())
	}
	return b.String()
}

func (p *PtmPacket) timestampString() string {
	valStr := getValStr(64, 64, p.timestamp, true, int(p.tsUpdate))
	var b strings.Builder
	b.WriteString("TS=")
	b.WriteString(valStr)
	b.WriteString(fmt.Sprintf("(%d); ", p.timestamp))
	if p.ccValid {
		b.WriteString(p.cycleCountString())
	}
	return b.String()
}

func (p *PtmPacket) cycleCountString() string {
	return fmt.Sprintf("Cycles=%d; ", p.cycleCount)
}

func packetTypeName(t pktType) (string, string) {
	switch t {
	case ptmPktNotSync:
		return "NOTSYNC", "PTM Not Synchronised"
	case ptmPktIncompleteEOT:
		return "INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"
	case ptmPktNoError:
		return "NO_ERROR", "Error type not set"
	case ptmPktBadSequence:
		return "BAD_SEQUENCE", "Invalid sequence in packet"
	case ptmPktReserved:
		return "RESERVED", "Reserved Packet Header"
	case ptmPktBranchAddress:
		return "BRANCH_ADDRESS", "Branch address packet"
	case ptmPktAsync:
		return "ASYNC", "Alignment Synchronisation Packet"
	case ptmPktISync:
		return "ISYNC", "Instruction Synchronisation packet"
	case ptmPktTrigger:
		return "TRIGGER", "Trigger Event packet"
	case ptmPktWPUpdate:
		return "WP_UPDATE", "Waypoint update packet"
	case ptmPktIgnore:
		return "IGNORE", "Ignore packet"
	case ptmPktContextID:
		return "CTXTID", "Context ID packet"
	case ptmPktVMID:
		return "VMID", "VM ID packet"
	case ptmPktAtom:
		return "ATOM", "Atom packet"
	case ptmPktTimestamp:
		return "TIMESTAMP", "Timestamp packet"
	case ptmPktExceptionRet:
		return "ERET", "Exception return packet"
	default:
		return "UNKNOWN", "Unknown packet type"
	}
}

func getValStr(totalBits int, validBits int, value uint64, asHex bool, updateBits int) string {
	if totalBits < 4 || totalBits > 64 {
		return ""
	}
	if asHex {
		numHexChars := totalBits / 4
		if totalBits%4 > 0 {
			numHexChars++
		}
		validChars := validBits / 4
		if validBits%4 > 0 {
			validChars++
		}
		var b strings.Builder
		b.WriteString("0x")
		if validChars < numHexChars {
			b.WriteString(strings.Repeat("?", numHexChars-validChars))
		}
		format := fmt.Sprintf("%%0%dX", validChars)
		if validBits > 32 {
			b.WriteString(fmt.Sprintf(format, value))
		} else {
			b.WriteString(fmt.Sprintf(format, uint32(value)))
		}
		if validBits < totalBits {
			b.WriteString(fmt.Sprintf(" (%d:0)", validBits-1))
		}
		if updateBits > 0 {
			updateMask := ^uint64(0) >> (64 - updateBits)
			b.WriteString(fmt.Sprintf(" ~[0x%X]", value&updateMask))
		}
		return b.String()
	}

	valStr := ""
	if validBits < totalBits {
		valStr += "??"
	}
	if validBits > 32 {
		valStr += fmt.Sprintf("%d", value)
	} else {
		valStr += fmt.Sprintf("%d", uint32(value))
	}
	if validBits < totalBits {
		valStr += fmt.Sprintf(" (%d:0)", validBits-1)
	}
	return valStr
}
