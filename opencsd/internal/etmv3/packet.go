package etmv3

import (
	"fmt"
	"strings"

	"opencsd/internal/ocsd"
)

// PktType defines the various types of ETMv3 packets
type PktType int

const (
	// markers for unknown packets
	PktNoError       PktType = iota //!< no error in packet - supplimentary data.
	PktNotSync                      //!< no sync found yet
	PktIncompleteEOT                //!< flushing incomplete/empty packet at end of trace.

	// markers for valid packets
	PktBranchAddress
	PktASync
	PktCycleCount
	PktISync
	PktISyncCycle
	PktTrigger
	PktPHdr
	PktStoreFail
	PktOOOData
	PktOOOAddrPlc
	PktNormData
	PktDataSuppressed
	PktValNotTraced
	PktIgnore
	PktContextID
	PktVMID
	PktExceptionEntry
	PktExceptionExit
	PktTimestamp

	// internal processing types
	PktBranchOrBypassEOT

	// packet errors
	PktBadSequence  //!< invalid sequence for packet type
	PktBadTraceMode //!< invalid packet type for this trace mode.
	PktReserved     //!< packet type reserved.
)

func (pt PktType) String() string {
	switch pt {
	case PktNoError:
		return "PktNoError"
	case PktNotSync:
		return "NOTSYNC"
	case PktIncompleteEOT:
		return "PktIncompleteEOT"
	case PktBranchAddress:
		return "Branch Address"
	case PktASync:
		return "A-Sync"
	case PktCycleCount:
		return "Cycle Count"
	case PktISync:
		return "I-Sync"
	case PktISyncCycle:
		return "I-Sync (CC)"
	case PktTrigger:
		return "Trigger"
	case PktPHdr:
		return "P-Header"
	case PktStoreFail:
		return "Store Fail"
	case PktOOOData:
		return "Out of Order Data"
	case PktOOOAddrPlc:
		return "Out of Order Address Placeholder"
	case PktNormData:
		return "Normal Data"
	case PktDataSuppressed:
		return "Data Suppressed"
	case PktValNotTraced:
		return "Value Not Traced"
	case PktIgnore:
		return "Ignore"
	case PktContextID:
		return "Context ID"
	case PktVMID:
		return "VMID"
	case PktExceptionEntry:
		return "Exception Entry"
	case PktExceptionExit:
		return "Exception Exit"
	case PktTimestamp:
		return "Timestamp"
	case PktBranchOrBypassEOT:
		return "PktBranchOrBypassEOT"
	case PktBadSequence:
		return "PktBadSequence"
	case PktBadTraceMode:
		return "PktBadTraceMode"
	case PktReserved:
		return "PktReserved"
	default:
		return "Unknown PktType"
	}
}

type Excep struct {
	Type    ocsd.ArmV7Exception
	Number  uint16
	Present bool
}

type Context struct {
	CurrAltIsa      bool   //!< current Alt ISA flag for Tee / T32 (used if not in present packet)
	CurrNS          bool   //!< current NS flag  (used if not in present packet)
	CurrHyp         bool   //!< current Hyp flag  (used if not in present packet)
	Updated         bool   //!< context flags updated
	ExceptionCancel bool   //!< cancel bit from ETMv3 exception branch address byte
	UpdatedC        bool   //!< updated CtxtID
	UpdatedV        bool   //!< updated VMID
	CtxtID          uint32 //!< Context ID
	VMID            uint8  //!< VMID
}

type Data struct {
	Value      uint32 //!< Data value
	Addr       uint64 //!< current data address
	OooTag     uint8  //!< Out of order data tag.
	BE         bool   //!< data transfers big-endian
	UpdateBE   bool   //!< updated Be flag
	UpdateAddr bool   //!< updated address
	UpdateDVal bool   //!< updated data value
}

type ISyncInfo struct {
	Reason        ocsd.ISyncReason
	HasCycleCount bool //!< updated cycle count
	HasLSipAddr   bool //!< main address is load-store instuction, data address is overlapping instruction @ start of trace
	NoAddress     bool //!< data only ISync
}

// Packet encapsulates an ETMv3 trace packet and intra-packet state
type Packet struct {
	Type PktType //!< Primary packet type.

	CurrISA ocsd.ISA //!< current ISA
	PrevISA ocsd.ISA //!< ISA in previous packet

	Context   Context   //!< current context
	Addr      uint64    //!< current Addr
	ISyncInfo ISyncInfo //!< i-sync info
	Exception Excep     //!< exception info

	ExceptionCancel bool         //!< cancel bit from ETMv3 exception branch address byte
	Atom            ocsd.PktAtom //!< atom elements - non zero number indicates valid atom count
	PHdrFmt         uint8        //!< if atom elements, associated phdr format
	CycleCount      uint32       //!< cycle count associated with this packet

	Timestamp    uint64 //!< current timestamp value
	TsUpdateBits uint8  //!< bits of ts updated this packet (if TS packet)

	Data Data //!< data transfer values

	AddrPktBits int //!< number of address bits updated by the current branch address packet

	ErrType PktType //!< Basic packet type if primary type indicates error or incomplete
}

func (p *Packet) Clear() {
	// Clears dynamic packet elements for a new packet but retains persistent state
	// like Timestamp, Addr, Context, and ISA.
	p.Type = PktNoError
	p.ErrType = PktNoError
	p.PrevISA = p.CurrISA
	p.Context.Updated = false
	p.Context.UpdatedC = false
	p.Context.UpdatedV = false
	p.Exception = Excep{}
	p.ISyncInfo = ISyncInfo{}
	p.ExceptionCancel = false
	p.Atom = ocsd.PktAtom{}
	p.PHdrFmt = 0
	p.CycleCount = 0
	p.TsUpdateBits = 0
	p.Data.UpdateBE = false
	p.Data.UpdateAddr = false
	p.Data.UpdateDVal = false
}

func (p *Packet) ResetState() {
	p.Clear()
	p.CurrISA = ocsd.ISAArm
	p.PrevISA = ocsd.ISAArm
	p.Context = Context{}
	p.Data = Data{}
}

func (p *Packet) IsBadPacket() bool {
	return p.Type >= PktBadSequence
}

func (p *Packet) UpdateAddress(partAddrVal uint64, updateBits int) {
	mask := uint64(0xFFFFFFFF)
	if updateBits < 32 {
		mask >>= (32 - updateBits)
	}
	p.Addr = (p.Addr & ^mask) | (partAddrVal & mask)
	p.AddrPktBits = updateBits
}

func (p *Packet) UpdateTimestamp(tsVal uint64, updateBits uint8) {
	if updateBits == 0 {
		return
	}
	var mask uint64
	if updateBits >= 64 {
		mask = ^uint64(0)
	} else {
		mask = uint64((1 << updateBits) - 1)
	}
	p.Timestamp = (p.Timestamp & ^mask) | (tsVal & mask)
	p.TsUpdateBits = updateBits
}

func (p *Packet) SetException(exType ocsd.ArmV7Exception, num uint16) {
	p.Exception.Type = exType
	p.Exception.Number = num
	p.Exception.Present = true
}

func (p *Packet) SetExceptionWithCancel(exType ocsd.ArmV7Exception, num uint16, cancel bool) {
	p.SetException(exType, num)
	p.ExceptionCancel = cancel
}

func (p *Packet) UpdateISA(isa ocsd.ISA) {
	p.PrevISA = p.CurrISA
	p.CurrISA = isa
}

func (p *Packet) UpdateAtomFromPHdr(pHdr uint8, cycleAccurate bool) bool {
	// Ported from trc_pkt_elem_etmv3.cpp UpdateAtomFromPHdr
	isValid := true
	p.Atom.EnBits = 0
	p.Atom.Num = 0

	if !cycleAccurate {
		// Non-cycle-accurate mode
		if (pHdr & 0x3) == 0x0 {
			// Format 1 (non-CA)
			p.PHdrFmt = 1
			e := (pHdr >> 2) & 0xF
			n := uint8(0)
			if (pHdr & 0x40) != 0 {
				n = 1
			}
			p.Atom.Num = e + n
			p.Atom.EnBits = (uint32(1) << e) - 1
		} else if (pHdr & 0x3) == 0x2 {
			// Format 2 (non-CA)
			p.PHdrFmt = 2
			p.Atom.Num = 2
			p.Atom.EnBits = 0
			if (pHdr & 0x8) == 0 {
				p.Atom.EnBits |= 1
			}
			if (pHdr & 0x4) == 0 {
				p.Atom.EnBits |= 2
			}
		} else {
			isValid = false
		}
	} else {
		// Cycle-accurate mode
		pHdrCode := pHdr & 0xA3
		switch pHdrCode {
		case 0x80:
			// Format 1 (CA)
			p.PHdrFmt = 1
			e := (pHdr >> 2) & 0x7
			n := uint8(0)
			if (pHdr & 0x40) != 0 {
				n = 1
			}
			p.Atom.Num = e + n
			if p.Atom.Num > 0 {
				p.Atom.EnBits = (uint32(1) << e) - 1
				p.CycleCount = uint32(e + n)
			} else {
				isValid = false // deprecated 8b'10000000 code
			}
		case 0x82:
			// Format 2 or 4 (CA)
			if (pHdr & 0x10) != 0 {
				// Format 4 (CA)
				p.PHdrFmt = 4
				p.Atom.Num = 1
				p.CycleCount = 0
				if (pHdr & 0x04) != 0 {
					p.Atom.EnBits = 0
				} else {
					p.Atom.EnBits = 1
				}
			} else {
				// Format 2 (CA)
				p.PHdrFmt = 2
				p.Atom.Num = 2
				p.CycleCount = 1
				p.Atom.EnBits = 0
				if (pHdr & 0x8) == 0 {
					p.Atom.EnBits |= 1
				}
				if (pHdr & 0x4) == 0 {
					p.Atom.EnBits |= 2
				}
			}
		case 0xA0:
			// Format 3 (CA)
			p.PHdrFmt = 3
			p.CycleCount = uint32(((pHdr >> 2) & 7) + 1)
			e := uint8(0)
			if (pHdr & 0x40) != 0 {
				e = 1
			}
			p.Atom.Num = e
			p.Atom.EnBits = uint32(e)
		default:
			isValid = false
		}
	}

	return isValid
}

// packetTypeNameDesc returns the C++ name and description strings for a packet type.
func packetTypeNameDesc(pt PktType) (string, string) {
	switch pt {
	case PktNotSync:
		return "NOTSYNC", "Trace Stream not synchronised"
	case PktIncompleteEOT:
		return "INCOMPLETE_EOT.", "Incomplete packet at end of trace data."
	case PktBranchAddress:
		return "BRANCH_ADDRESS", "Branch address."
	case PktASync:
		return "A_SYNC", "Alignment Synchronisation."
	case PktCycleCount:
		return "CYCLE_COUNT", "Cycle Count."
	case PktISync:
		return "I_SYNC", "Instruction Packet synchronisation."
	case PktISyncCycle:
		return "I_SYNC_CYCLE", "Instruction Packet synchronisation with cycle count."
	case PktTrigger:
		return "TRIGGER", "Trace Trigger Event."
	case PktPHdr:
		return "P_HDR", "Atom P-header."
	case PktStoreFail:
		return "STORE_FAIL", "Data Store Failed."
	case PktOOOData:
		return "OOO_DATA", "Out of Order data value packet."
	case PktOOOAddrPlc:
		return "OOO_ADDR_PLC", "Out of Order data address placeholder."
	case PktNormData:
		return "NORM_DATA", "Data trace packet."
	case PktDataSuppressed:
		return "DATA_SUPPRESSED", "Data trace suppressed."
	case PktValNotTraced:
		return "VAL_NOT_TRACED", "Data trace value not traced."
	case PktIgnore:
		return "IGNORE", "Packet ignored."
	case PktContextID:
		return "CONTEXT_ID", "Context ID change."
	case PktVMID:
		return "VMID", "VMID change."
	case PktExceptionEntry:
		return "EXCEPTION_ENTRY", "Exception entry data marker."
	case PktExceptionExit:
		return "EXCEPTION_EXIT", "Exception return."
	case PktTimestamp:
		return "TIMESTAMP", "Timestamp Value."
	case PktBadSequence:
		return "BAD_SEQUENCE", "Invalid sequence for packet type."
	case PktBadTraceMode:
		return "BAD_TRACEMODE", "Invalid packet type for this trace mode."
	default:
		return "I_RESERVED", "Reserved Packet Header"
	}
}

// addrValStr formats a 32-bit address like C++ getValStr: uppercase hex, 8 digits,
// with an optional ~[0xNN] suffix showing the low pktBits of the value.
func addrValStr(addr uint64, pktBits int) string {
	s := fmt.Sprintf("0x%08X", uint32(addr))
	if pktBits > 0 && pktBits <= 32 {
		mask := uint32(0xFFFFFFFF)
		if pktBits < 32 {
			mask = uint32((1 << pktBits) - 1)
		}
		s += fmt.Sprintf(" ~[0x%X]", uint32(addr)&mask)
	}
	return s
}

// buildISAStr returns the ISA string matching C++ getISAStr output (e.g. "ISA=ARM(32); ").
func buildISAStr(isa ocsd.ISA) string {
	switch isa {
	case ocsd.ISAArm:
		return "ISA=ARM(32); "
	case ocsd.ISAThumb2:
		return "ISA=Thumb2; "
	case ocsd.ISAJazelle:
		return "ISA=Jazelle; "
	case ocsd.ISATee:
		return "ISA=ThumbEE; "
	default:
		return "ISA=Unknown; "
	}
}

// buildAtomStrCA returns the atom string matching C++ getAtomStr, supporting cycle-accurate mode.
func (p *Packet) buildAtomStrCA() string {
	var oss strings.Builder
	bitpattern := p.Atom.EnBits
	if p.CycleCount == 0 {
		// non-cycle-accurate
		for i := 0; i < int(p.Atom.Num); i++ {
			if bitpattern&1 == 1 {
				oss.WriteString("E")
			} else {
				oss.WriteString("N")
			}
			bitpattern >>= 1
		}
	} else {
		switch p.PHdrFmt {
		case 1:
			for i := 0; i < int(p.Atom.Num); i++ {
				if bitpattern&1 == 1 {
					oss.WriteString("WE")
				} else {
					oss.WriteString("WN")
				}
				bitpattern >>= 1
			}
		case 2:
			oss.WriteString("W")
			for i := 0; i < int(p.Atom.Num); i++ {
				if bitpattern&1 == 1 {
					oss.WriteString("E")
				} else {
					oss.WriteString("N")
				}
				bitpattern >>= 1
			}
		case 3:
			for i := uint32(0); i < p.CycleCount; i++ {
				oss.WriteString("W")
			}
			if p.Atom.Num > 0 {
				if bitpattern&1 == 1 {
					oss.WriteString("E")
				} else {
					oss.WriteString("N")
				}
			}
		}
		fmt.Fprintf(&oss, "; Cycles=%d", p.CycleCount)
	}
	return oss.String()
}

// buildISyncStr returns the ISync string matching C++ getISyncStr output.
func (p *Packet) buildISyncStr() string {
	var oss strings.Builder
	reasons := []string{"Periodic", "Trace Enable", "Restart Overflow", "Debug Exit"}
	reason := "Unknown"
	if int(p.ISyncInfo.Reason) < len(reasons) {
		reason = reasons[p.ISyncInfo.Reason]
	}
	fmt.Fprintf(&oss, "(%s); ", reason)
	if !p.ISyncInfo.NoAddress {
		if p.ISyncInfo.HasLSipAddr {
			fmt.Fprintf(&oss, "Data Instr Addr=0x%08x; ", uint32(p.Addr))
		} else {
			fmt.Fprintf(&oss, "Addr=0x%08x; ", uint32(p.Addr))
		}
	}
	if p.Context.CurrNS {
		oss.WriteString("NS; ")
	} else {
		oss.WriteString("S; ")
	}
	if p.Context.CurrHyp {
		oss.WriteString("Hyp; ")
	} else {
		oss.WriteString(" ")
	}
	if p.Context.UpdatedC {
		fmt.Fprintf(&oss, "CtxtID=%x; ", p.Context.CtxtID)
	}
	if p.ISyncInfo.NoAddress {
		return oss.String()
	}
	oss.WriteString(buildISAStr(p.CurrISA))
	if p.ISyncInfo.HasCycleCount {
		fmt.Fprintf(&oss, "Cycles=%d; ", p.CycleCount)
	}
	return oss.String()
}

// buildBranchAddressStr returns the branch address string matching C++ getBranchAddressStr.
func (p *Packet) buildBranchAddressStr() string {
	var oss strings.Builder
	oss.WriteString("Addr=")
	oss.WriteString(addrValStr(p.Addr, p.AddrPktBits))
	oss.WriteString("; ")
	if p.CurrISA != p.PrevISA {
		oss.WriteString(buildISAStr(p.CurrISA))
	}
	if p.Context.Updated {
		if p.Context.CurrNS {
			oss.WriteString("NS; ")
		} else {
			oss.WriteString("S; ")
		}
		if p.Context.CurrHyp {
			oss.WriteString("Hyp; ")
		}
	}
	if p.Exception.Present {
		oss.WriteString(p.buildExcepStr())
	}
	return oss.String()
}

var armV7ExcepNames = []string{
	"No Exception", "Debug Halt", "SMC", "Hyp",
	"Async Data Abort", "Jazelle", "Reserved", "Reserved",
	"PE Reset", "Undefined Instr", "SVC", "Prefetch Abort",
	"Data Fault", "Generic", "IRQ", "FIQ",
}

// buildExcepStr returns the exception string matching C++ getExcepStr (ARMv7 non-CM case).
func (p *Packet) buildExcepStr() string {
	var oss strings.Builder
	oss.WriteString("Exception=")
	num := int(p.Exception.Number)
	if num < len(armV7ExcepNames) {
		oss.WriteString(armV7ExcepNames[num])
	} else {
		fmt.Fprintf(&oss, "IRQ%d", num-0x10)
	}
	oss.WriteString("; ")
	if p.ExceptionCancel {
		oss.WriteString("; Cancel prev instr")
	}
	return oss.String()
}

func (p *Packet) String() string {
	name, desc := packetTypeNameDesc(p.Type)
	s := name + " : " + desc
	switch p.Type {
	case PktBadSequence, PktBadTraceMode:
		errName, _ := packetTypeNameDesc(p.ErrType)
		s += "[" + errName + "]"
	case PktBranchAddress:
		s += "; " + p.buildBranchAddressStr()
	case PktISync, PktISyncCycle:
		s += "; " + p.buildISyncStr()
	case PktPHdr:
		s += "; " + p.buildAtomStrCA()
	case PktCycleCount:
		s += fmt.Sprintf("; Cycles=%d", p.CycleCount)
	case PktContextID:
		s += fmt.Sprintf("; CtxtID=0x%x", p.Context.CtxtID)
	case PktVMID:
		s += fmt.Sprintf("; VMID=0x%x", uint32(p.Context.VMID))
	case PktTimestamp:
		s += fmt.Sprintf("; TS=0x%x (%d) ", p.Timestamp, p.Timestamp)
	}
	return s
}

func (p *Packet) GetISAStr() string {
	switch p.CurrISA {
	case ocsd.ISAArm:
		return "ARM(32)"
	case ocsd.ISAThumb2:
		return "Thumb2"
	case ocsd.ISAJazelle:
		return "Jazelle"
	case ocsd.ISATee:
		return "ThumbEE"
	default:
		return "Unknown"
	}
}

func (p *Packet) GetISyncStr() string {
	switch p.ISyncInfo.Reason {
	case ocsd.ISyncPeriodic:
		return "Periodic"
	case ocsd.ISyncTraceEnable:
		return "Trace Enable"
	case ocsd.ISyncTraceRestartAfterOverflow:
		return "Restart Overflow"
	case ocsd.ISyncDebugExit:
		return "Debug Exit"
	default:
		return "Unknown"
	}
}

func (p *Packet) GetAtomStr() string {
	if p.Atom.Num == 0 {
		return ""
	}
	var s strings.Builder
	bitpattern := p.Atom.EnBits
	for i := 0; i < int(p.Atom.Num); i++ {
		if (bitpattern & 1) == 1 {
			s.WriteString("E")
		} else {
			s.WriteString("N")
		}
		bitpattern >>= 1
	}
	return s.String()
}
