package itm

import (
	"fmt"
	"strings"
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

// Reset initializes packet to a clean state.
func (p *Packet) Reset() {
	p.Type = PktReserved
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

var valMasks = [...]uint32{0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF}

// SetValue sets the packet payload value.
func (p *Packet) SetValue(val uint32, valSzBytes uint8) {
	p.ValSz = valSzBytes
	if p.ValSz < 1 || p.ValSz > 4 {
		p.ValSz = 4
	}
	p.Value = val & valMasks[p.ValSz-1]
}

// SetExtValue sets the extended value (size is always 5).
func (p *Packet) SetExtValue(extVal uint64) {
	p.Value = uint32(extVal & 0xFFFFFFFF)
	p.ValExt = uint8((extVal >> 32) & 0xFF)
	p.ValSz = 5
}

// ExtValue gets the 38-bit extended value.
func (p *Packet) ExtValue() uint64 {
	return uint64(p.Value) | (uint64(p.ValExt) << 32)
}

// IsBadPacket returns true if the packet type indicates a bad sequence or reserved protocol.
func (p *Packet) IsBadPacket() bool {
	return p.Type >= PktBadSequence
}

// String provides a string representation of the packet, matching C++ trc_pkt_elem_itm formatting.
func (p *Packet) String() string {
	var sb strings.Builder
	name, desc := p.typeNameAndDesc()
	sb.WriteString(name)
	sb.WriteString(": ")

	switch p.Type {
	case PktSWIT:
		fmt.Fprintf(&sb, "{src id: 0x%02x}  ", p.SrcID)
		p.writeHexVal(&sb)
	case PktDWT:
		fmt.Fprintf(&sb, "{desc: 0x%02x} ", p.SrcID)
		p.writeDwtPacketBody(&sb)
	case PktTSLocal:
		p.writeTsLocalPacketBody(&sb)
	case PktTSGlobal1:
		p.writeTsGlobal1PacketBody(&sb)
	case PktTSGlobal2:
		p.writeTsGlobal2PacketBody(&sb)
	case PktExtension:
		p.writeExtensionPacketBody(&sb)
	case PktIncompleteEOT, PktBadSequence:
		errName, _ := (&Packet{Type: p.ErrType}).typeNameAndDesc()
		fmt.Fprintf(&sb, "[Init type: %s] ", errName)
	}

	sb.WriteString("; '")
	sb.WriteString(desc)
	sb.WriteString("'")
	return sb.String()
}

func (p *Packet) typeNameAndDesc() (string, string) {
	switch p.Type {
	case PktNotSync:
		return "ITM_NOTSYNC", "ITM data stream not synchronised"
	case PktIncompleteEOT:
		return "ITM_INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"
	case PktAsync:
		return "ITM_ASYNC", "Alignment synchronisation packet"
	case PktOverflow:
		return "ITM_OVERFLOW", "ITM overflow packet"
	case PktSWIT:
		return "ITM_SWIT", "Software Stimulus write packet"
	case PktDWT:
		return "ITM_DWT", "DWT hardware stimulus write"
	case PktTSLocal:
		return "ITM_TS_LOCAL", "Local Timestamp"
	case PktTSGlobal1:
		return "ITM_GTS_1", "Global Timestamp [25:0]"
	case PktTSGlobal2:
		return "ITM_GTS_2", "Global Timestamp [{63|42}:26]"
	case PktExtension:
		return "ITM_EXTENSION", "Extension packet"
	case PktBadSequence:
		return "ITM_BAD_SEQUENCE", "Invalid sequence in packet"
	case PktReserved:
		return "ITM_RESERVED", "Reserved Packet Header"
	default:
		return "ITM_UNKNOWN", "ERROR: unknown packet type"
	}
}

func (p *Packet) writeHexVal(sb *strings.Builder) {
	valSz := int(p.ValSz)
	if valSz < 1 || valSz > 4 {
		valSz = 4
	}
	fmt.Fprintf(sb, "0x%0*x", valSz*2, p.Value)
}

var dwtFlags = [...]struct {
	bit DwtEcntr
	str string
}{
	{DwtEcntrCPI, "CPI"},
	{DwtEcntrEXC, "EXC"},
	{DwtEcntrSLP, "Sleep"},
	{DwtEcntrLSU, "LSU"},
	{DwtEcntrFLD, "Fold"},
	{DwtEcntrCYC, "CYC"},
}

var dwtExcepFn = [...]string{"reserved", "entered", "exited", "returned to"}

func (p *Packet) writeDwtPacketBody(sb *strings.Builder) {
	if p.SrcID == 0 {
		fmt.Fprintf(sb, "[Event Counter: 0x%02x; Flags: ", p.Value)
		for _, f := range dwtFlags {
			if p.Value&uint32(f.bit) != 0 {
				fmt.Fprintf(sb, " %s ", f.str)
			} else {
				sb.WriteString(" --- ")
			}
		}
		sb.WriteString("] ")
		return
	}

	if p.SrcID == 1 {
		action := (p.Value >> 12) & 0x3
		fmt.Fprintf(sb, "[Exception Num:  0x%04x(%s) ]", p.Value&0x1FF, dwtExcepFn[action])
		return
	}

	if p.SrcID == 2 {
		sb.WriteString("[PC Sample: ")
		p.writeHexVal(sb)
		sb.WriteString("] ")
		return
	}

	if p.SrcID >= 8 && p.SrcID <= 23 {
		dtType := (p.SrcID >> 3) & 0x3
		dtRW := p.SrcID & 0x1
		dtComp := (p.SrcID >> 1) & 0x3
		if dtType == 0x1 && dtRW == 0 {
			fmt.Fprintf(sb, "[Data Trc: comp=%d; PC Value=", dtComp)
			p.writeHexVal(sb)
			sb.WriteString(" ] ")
			return
		}
		if dtType == 0x1 && dtRW == 1 {
			fmt.Fprintf(sb, "[Data Trc: comp=%d; Address=", dtComp)
			p.writeHexVal(sb)
			sb.WriteString(" ] ")
			return
		}
		if dtType == 0x2 {
			if dtRW == 1 {
				fmt.Fprintf(sb, "[Data Trc: comp=%d; Val write: ", dtComp)
			} else {
				fmt.Fprintf(sb, "[Data Trc: comp=%d; Val read: ", dtComp)
			}
			p.writeHexVal(sb)
			sb.WriteString("] ")
			return
		}
	}

	sb.WriteString("[Reserved discriminator value] ")
}

var tsLocalTypes = [...]string{
	"TS Sync",
	"TS Delayed",
	"TS Sync, Packet Delayed",
	"TS Delayed, Packet Delayed",
}

func (p *Packet) writeTsLocalPacketBody(sb *strings.Builder) {
	p.writeHexVal(sb)
	fmt.Fprintf(sb, " { %s }", tsLocalTypes[p.SrcID&3])
}

var tsGlobal1BitSizes = [...]int{6, 13, 20, 25}

func (p *Packet) writeTsGlobal1PacketBody(sb *strings.Builder) {
	idx := max(int(p.ValSz)-1, 0)
	if idx >= len(tsGlobal1BitSizes) {
		idx = len(tsGlobal1BitSizes) - 1
	}

	fmt.Fprintf(sb, "{ TS bits [%d:0]", tsGlobal1BitSizes[idx])
	if p.SrcID&0x1 != 0 {
		sb.WriteString(", Clk change")
	}
	if p.SrcID&0x2 != 0 {
		sb.WriteString(", Clk wrap")
	}
	sb.WriteString("} ")
	p.writeHexVal(sb)
}

func (p *Packet) writeTsGlobal2PacketBody(sb *strings.Builder) {
	if p.ValSz == 5 {
		sb.WriteString("{ TS bits [63:26]} ")
		fmt.Fprintf(sb, "0x%02x%08x", p.ValExt, p.Value)
	} else {
		sb.WriteString("{ TS bits [47:26]} ")
		p.writeHexVal(sb)
	}
}

func (p *Packet) writeExtensionPacketBody(sb *strings.Builder) {
	bitsize := int(p.SrcID&0x1F) + 1
	if bitsize == 3 && (p.SrcID&0x80) == 0 {
		fmt.Fprintf(sb, "{stim port page} 0x%02x", p.Value)
		return
	}
	width := (bitsize / 4) + 1
	fmt.Fprintf(sb, "{unknown extension type, %d bits } 0x%0*x", bitsize, width, p.Value)
}
