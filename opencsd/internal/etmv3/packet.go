package etmv3

import (
	"fmt"

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
		return "I_NOT_SYNC"
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
	Type     ocsd.ArmV7Exception
	Number   uint16
	Present  bool
	Cancel   bool
	CmType   bool
	CmResume uint8
	CmIrqN   uint16
}

type Context struct {
	CurrAltIsa bool   //!< current Alt ISA flag for Tee / T32 (used if not in present packet)
	CurrNS     bool   //!< current NS flag  (used if not in present packet)
	CurrHyp    bool   //!< current Hyp flag  (used if not in present packet)
	Updated    bool   //!< context flags updated
	UpdatedC   bool   //!< updated CtxtID
	UpdatedV   bool   //!< updated VMID
	CtxtID     uint32 //!< Context ID
	VMID       uint8  //!< VMID
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

	Atom       ocsd.PktAtom //!< atom elements - non zero number indicates valid atom count
	PHdrFmt    uint8        //!< if atom elements, associated phdr format
	CycleCount uint32       //!< cycle count associated with this packet

	Timestamp    uint64 //!< current timestamp value
	TsUpdateBits uint8  //!< bits of ts updated this packet (if TS packet)

	Data Data //!< data transfer values

	ErrType PktType //!< Basic packet type if primary type indicates error or incomplete
}

func (p *Packet) Clear() {
	// Clears dynamic packet elements for a new packet but retains persistent state
	// like Timestamp, Addr, Context, and ISA.
	p.Type = PktNoError
	p.ErrType = PktNoError
	p.Context.Updated = false
	p.Context.UpdatedC = false
	p.Context.UpdatedV = false
	p.Exception = Excep{}
	p.ISyncInfo = ISyncInfo{}
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

func (p *Packet) SetException(exType ocsd.ArmV7Exception, num uint16, cancel, cmType bool, irqN uint16, resume uint8) {
	p.Exception.Type = exType
	p.Exception.Number = num
	p.Exception.Present = true
	p.Exception.Cancel = cancel
	p.Exception.CmType = cmType
	p.Exception.CmIrqN = irqN
	p.Exception.CmResume = resume
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

func (p *Packet) String() string {
	s := fmt.Sprintf("ETMv3 Pkt [%s]", p.Type.String())
	if p.Type == PktPHdr {
		s += fmt.Sprintf(" Atoms: %d (%08b)", p.Atom.Num, p.Atom.EnBits)
	} else if p.Type == PktISync {
		s += fmt.Sprintf(" Addr: 0x%x", p.Addr)
	} else if p.Type == PktBranchAddress {
		s += fmt.Sprintf(" Addr: 0x%x", p.Addr)
	}
	return s
}
