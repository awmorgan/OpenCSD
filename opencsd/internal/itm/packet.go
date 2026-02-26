package itm

import (
	"fmt"
)

// PktType represents the ITM packet type.
type PktType int

const (
	/* markers for unknown packets  / state*/
	PktNotSync       PktType = iota /**< Not synchronised */
	PktIncompleteEOT                /**< Incomplete packet flushed at end of trace. */
	PktNoErrType                    /**< No error in error packet marker. */

	/* valid packet types */
	PktAsync     /**< sync packet */
	PktOverflow  /**< overflow packet */
	PktSWIT      /**< Software stimulus packet */
	PktDWT       /**< DWT hardware stimulus packet */
	PktTSLocal   /**< Timestamp packet using local timestamp source */
	PktTSGlobal1 /**< Timestamp packet bits [25:0] from the global timestamp source */
	PktTSGlobal2 /**< Timestamp packet bits [63:26] or [47:26] from the global timestamp source */
	PktExtension /**< Extension packet */

	/* packet errors */
	PktBadSequence
	PktReserved
)

// DwtEcntr represents DWT hardware event counters.
type DwtEcntr uint8

const (
	DwtEcntrCPI DwtEcntr = 0x01
	DwtEcntrEXC DwtEcntr = 0x02
	DwtEcntrSLP DwtEcntr = 0x04
	DwtEcntrLSU DwtEcntr = 0x08
	DwtEcntrFLD DwtEcntr = 0x10
	DwtEcntrCYC DwtEcntr = 0x20
)

// Packet represents an incoming ITM packet.
type Packet struct {
	Type PktType /**< ITM packet type */
	/**! Source ID uses:
		 - SWIT: value of source channel [4:0],
	     - DWT: value of discriminator   [4:0],
		 - LTS: TC flags for Local TS pkt [1:0],
		 - GTS1: clk wrap [1] / freq change [0] bits,
		 - Ext: Src SW(0)/HW(1) [7], N size - N:0 value bit length [4:0],
	*/
	SrcID   uint8
	Value   uint32  /**< packet data payload - interpretation depends on type */
	ValSz   uint8   /**< size of value in bytes */
	ValExt  uint8   /**< additional value bits to handle top of [63:26] timestamp packet (38 bits of ts) */
	ErrType PktType /**< Initial type of packet if type indicates bad sequence. */
}

// InitPacket initializes packet to clean state.
func (p *Packet) InitPacket() {
	p.Type = PktNotSync
	p.SrcID = 0
	p.Value = 0
	p.ValSz = 0
	p.ValExt = 0
	p.ErrType = PktNoErrType
}

// SetPacketType sets the packet type.
func (p *Packet) SetPacketType(pktType PktType) {
	p.Type = pktType
}

// UpdateErrType updates the error type and sets the packet to the given error type.
func (p *Packet) UpdateErrType(errType PktType) {
	p.ErrType = p.Type // original type is the err type
	p.Type = errType   // mark main type as an error
}

// SetSrcID sets the packet source ID.
func (p *Packet) SetSrcID(srcID uint8) {
	p.SrcID = srcID
}

// SetValue sets the packet payload value.
func (p *Packet) SetValue(val uint32, valSzBytes uint8) {
	p.Value = val
	p.ValSz = valSzBytes
}

// SetExtValue sets the extended value (size is always 5).
func (p *Packet) SetExtValue(extVal uint64) {
	p.Value = uint32(extVal & 0xFFFFFFFF)
	p.ValExt = uint8((extVal >> 32) & 0x0F)
	p.ValSz = 5
}

// GetExtValue gets the 38-bit extended value.
func (p *Packet) GetExtValue() uint64 {
	return uint64(p.Value) | (uint64(p.ValExt) << 32)
}

// IsBadPacket returns true if the packet type indicates a bad sequence or reserved protocol.
func (p *Packet) IsBadPacket() bool {
	return p.Type >= PktBadSequence
}

// String provides a string representation of the packet.
func (p *Packet) String() string {
	name, desc := p.typeNameAndDesc()
	str := fmt.Sprintf("%s:%s", name, desc)

	switch p.Type {
	case PktSWIT:
		str += fmt.Sprintf("; %v; Port 0x%02X; Data 0x%08X", p.valSizeStr(), p.SrcID, p.Value)
	case PktDWT:
		str += fmt.Sprintf("; %s", p.dwtPacketStr())
	case PktTSLocal:
		str += fmt.Sprintf("; %s", p.tsLocalPacketStr())
	case PktTSGlobal1:
		str += fmt.Sprintf("; TS 25:0  0x%07X", p.Value)
	case PktTSGlobal2:
		str += fmt.Sprintf("; TS 63:26 0x%010X", p.GetExtValue())
	case PktExtension:
		valStr := ""
		if p.ValSz > 0 {
			switch p.ValSz {
			case 1, 2, 4:
				valStr = fmt.Sprintf("0x%08X", p.Value)
			case 5:
				valStr = fmt.Sprintf("0x%010X", p.GetExtValue())
			}
		} else {
			valStr = "<none>"
		}
		str += fmt.Sprintf("; Src %s; Val %s", func() string {
			if (p.SrcID & 0x80) != 0 {
				return "HW"
			}
			return "SW"
		}(), valStr)
	case PktBadSequence:
		name, _ = (&Packet{Type: p.ErrType}).typeNameAndDesc()
		str += fmt.Sprintf("[%s]", name)
	}
	return str
}

func (p *Packet) typeNameAndDesc() (string, string) {
	switch p.Type {
	case PktNotSync:
		return "NOTSYNC", "ITM not synchronised"
	case PktIncompleteEOT:
		return "INCOMPLETE_EOT", "Incomplete packet at end of trace"
	case PktAsync:
		return "ASYNC", "Alignment synchronisation packet"
	case PktOverflow:
		return "OVERFLOW", "Overflow packet"
	case PktSWIT:
		return "SWIT", "Software stimulus packet"
	case PktDWT:
		return "DWT", "Hardware stimulus packet"
	case PktTSLocal:
		return "TS_L", "Local timestamp packet"
	case PktTSGlobal1:
		return "TS_G1", "Global timestamp packet 1"
	case PktTSGlobal2:
		return "TS_G2", "Global timestamp packet 2"
	case PktExtension:
		return "EXTENSION", "Extension packet"
	case PktBadSequence:
		return "BAD_SEQUENCE", "Invalid sequence in packet"
	case PktReserved:
		return "RESERVED", "Reserved packet header"
	default:
		return "UNKNOWN", "Unknown Packet Type"
	}
}

func (p *Packet) valSizeStr() string {
	switch p.ValSz {
	case 1:
		return "8 bit"
	case 2:
		return "16 bit"
	case 4:
		return "32 bit"
	default:
		return "Unsized"
	}
}

func (p *Packet) dwtPacketStr() string {
	str := p.valSizeStr()
	desc := ""

	if p.SrcID == 0 { // Event packet
		desc = "Event"
		val := p.Value
		if (val & uint32(DwtEcntrCPI)) != 0 {
			str += " CPI;"
		}
		if (val & uint32(DwtEcntrEXC)) != 0 {
			str += " EXC;"
		}
		if (val & uint32(DwtEcntrSLP)) != 0 {
			str += " SLP;"
		}
		if (val & uint32(DwtEcntrLSU)) != 0 {
			str += " LSU;"
		}
		if (val & uint32(DwtEcntrFLD)) != 0 {
			str += " FLD;"
		}
		if (val & uint32(DwtEcntrCYC)) != 0 {
			str += " CYC;"
		}
	} else if p.SrcID == 1 { // Exception Trace
		desc = "Exception"
		str += fmt.Sprintf("; Exception Num %03d", p.Value&0x1FF)
		action := (p.Value >> 12) & 0x3
		switch action {
		case 1:
			str += " Entered"
		case 2:
			str += " Exited"
		case 3:
			str += " Returned"
		}
	} else if p.SrcID == 2 { // PC sample
		desc = "PC Sample"
		str += fmt.Sprintf("; PC = 0x%08X", p.Value)
	} else if p.SrcID == 8 { // Data Trace PC value
		desc = "Data Trace PC Value"
		str += fmt.Sprintf("; PC = 0x%08X", p.Value)
	} else if p.SrcID == 9 || p.SrcID == 11 { // Data trace address
		desc = "Data Trace Address"
		str += fmt.Sprintf("; Addr = 0x%08X", p.Value)
	} else if p.SrcID >= 16 && p.SrcID <= 24 { // Data trace data
		desc = "Data Trace Data"
		str += fmt.Sprintf("; Data = 0x%08X", p.Value)
		op := (p.SrcID >> 1) & 0x3
		switch op {
		case 1:
			str += " (Read)"
		case 2:
			str += " (Write)"
		}
	} else {
		desc = "Unknown"
		str += fmt.Sprintf("; ID = 0x%02X; Data = 0x%08X", p.SrcID, p.Value)
	}

	return fmt.Sprintf("%s : %s", desc, str)
}

func (p *Packet) tsLocalPacketStr() string {
	tcDescs := []string{
		"TS Sync",
		"TS Delay",
		"TS Async",
		"TS delayed - async",
	}
	tcIdx := p.SrcID & 0x3
	return fmt.Sprintf("TC %s; TS = 0x%07X", tcDescs[tcIdx], p.Value)
}
