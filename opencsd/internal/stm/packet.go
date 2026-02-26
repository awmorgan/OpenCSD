package stm

import (
	"fmt"
)

// PktType represents STM protocol packet types.
// Contains both protocol packet types and markers for unsynced processor state
// and bad packet sequences.
type PktType int

const (
	// markers for unknown packets / state
	PktNotSync       PktType = iota // Not synchronised
	PktIncompleteEOT                // Incomplete packet flushed at end of trace.
	PktNoErrType                    // No error in error packet marker.

	// markers for valid packets
	PktAsync   // Alignment synchronisation packet
	PktVersion // Version packet
	PktFreq    // Frequency packet
	PktNull    // Null packet
	PktTrig    // Trigger event packet.

	PktGErr // Global error packet
	PktMErr // Master error packet

	PktM8  // Set current master
	PktC8  // Set lower 8 bits of current channel
	PktC16 // Set current channel

	PktFlag // Flag packet

	PktD4  // 4 bit data payload packet
	PktD8  // 8 bit data payload packet
	PktD16 // 16 bit data payload packet
	PktD32 // 32 bit data payload packet
	PktD64 // 64 bit data payload packet

	// packet errors
	PktBadSequence // Incorrect protocol sequence
	PktReserved    // Reserved packet header / not supported by CS-STM
)

// TSType represents STM timestamp encoding type.
type TSType int

const (
	TSUnknown   TSType = iota // TS encoding unknown at present
	TSNatBinary               // TS encoding natural binary
	TSGrey                    // TS encoding grey coded
)

// Packet represents a trace packet with packet printing functionality
type Packet struct {
	Type PktType

	Master  uint8
	Channel uint16

	Timestamp uint64 // latest timestamp value as binary
	PktTSBits uint8  // timestamp bits updated this packet
	PktHasTS  uint8  // current packet has associated timestamp

	TSType TSType

	PktHasMarker uint8 // flag to indicate current packet has marker

	Payload struct {
		D8  uint8
		D16 uint16
		D32 uint32
		D64 uint64
	}

	ErrType PktType // Initial type of packet if type indicates bad sequence.
}

// InitStartState initializes packet state at start of decoder.
func (p *Packet) InitStartState() {
	p.Master = 0
	p.Channel = 0
	p.Timestamp = 0
	p.TSType = TSUnknown
	p.Type = PktNotSync
	p.InitNextPacket()
}

// InitNextPacket initializes state for next packet.
func (p *Packet) InitNextPacket() {
	p.ErrType = PktNoErrType
	p.PktTSBits = 0
	p.PktHasMarker = 0
	p.PktHasTS = 0
}

func (p *Packet) SetPacketType(typ PktType, bMarker bool) {
	p.Type = typ
	if bMarker {
		p.PktHasMarker = 1
	} else {
		p.PktHasMarker = 0
	}
}

func (p *Packet) UpdateErrType(errType PktType) {
	p.ErrType = p.Type
	p.Type = errType
}

func (p *Packet) SetMaster(master uint8) {
	p.Master = master
	p.Channel = 0 // M8 forces current channel to 0
}

func (p *Packet) SetChannel(channel uint16, b8Bit bool) {
	if b8Bit {
		p.Channel = (p.Channel & 0xFF00) | (channel & 0xFF)
	} else {
		p.Channel = channel
	}
}

func (p *Packet) SetTS(tsVal uint64, updatedBits uint8) {
	if updatedBits == 64 {
		p.Timestamp = tsVal
	} else {
		mask := (uint64(1) << updatedBits) - 1
		p.Timestamp &^= mask
		p.Timestamp |= tsVal & mask
	}
	p.PktTSBits = updatedBits
	p.PktHasTS = 1
}

func (p *Packet) OnVersionPkt(typ TSType) {
	p.TSType = typ
	p.Master = 0
	p.Channel = 0
}

func (p *Packet) SetD4Payload(value uint8) {
	p.Payload.D8 = value & 0xF
}

func (p *Packet) SetD8Payload(value uint8) {
	p.Payload.D8 = value
}

func (p *Packet) SetD16Payload(value uint16) {
	p.Payload.D16 = value
}

func (p *Packet) SetD32Payload(value uint32) {
	p.Payload.D32 = value
}

func (p *Packet) SetD64Payload(value uint64) {
	p.Payload.D64 = value
}

func (p *Packet) IsMarkerPkt() bool {
	return p.PktHasMarker != 0
}

func (p *Packet) IsTSPkt() bool {
	return p.PktHasTS != 0
}

func (p *Packet) IsBadPacket() bool {
	return p.Type >= PktBadSequence
}

func (p *Packet) String() string {
	var name, desc string
	addMarkerTS := false

	switch p.Type {
	case PktReserved:
		name, desc = "RESERVED", "Reserved Packet Header"
	case PktNotSync:
		name, desc = "NOTSYNC", "STM not synchronised"
	case PktIncompleteEOT:
		name, desc = "INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"
	case PktNoErrType:
		name, desc = "NO_ERR_TYPE", "Error type not set"
	case PktBadSequence:
		name, desc = "BAD_SEQUENCE", "Invalid sequence in packet"
	case PktAsync:
		name, desc = "ASYNC", "Alignment synchronisation packet"
	case PktVersion:
		name, desc = "VERSION", "Version packet"
	case PktFreq:
		name, desc = "FREQ", "Frequency packet"
	case PktNull:
		name, desc = "NULL", "Null packet"
	case PktTrig:
		name, desc = "TRIG", "Trigger packet"
		addMarkerTS = true
	case PktGErr:
		name, desc = "GERR", "Global Error"
	case PktMErr:
		name, desc = "MERR", "Master Error"
	case PktM8:
		name, desc = "M8", "Set current master"
	case PktC8:
		name, desc = "C8", "Set current channel"
	case PktC16:
		name, desc = "C16", "Set current channel"
	case PktFlag:
		name, desc = "FLAG", "Flag packet"
		addMarkerTS = true
	case PktD4:
		name, desc = "D4", "4 bit data"
		addMarkerTS = true
	case PktD8:
		name, desc = "D8", "8 bit data"
		addMarkerTS = true
	case PktD16:
		name, desc = "D16", "16 bit data"
		addMarkerTS = true
	case PktD32:
		name, desc = "D32", "32 bit data"
		addMarkerTS = true
	case PktD64:
		name, desc = "D64", "64 bit data"
		addMarkerTS = true
	default:
		name, desc = "UNKNOWN", "ERROR: unknown packet type"
	}

	if addMarkerTS {
		if p.IsMarkerPkt() {
			name += "M"
			desc += " + marker"
		}
		if p.IsTSPkt() {
			name += "TS"
			desc += " + timestamp"
		}
	}

	str := fmt.Sprintf("%s:%s", name, desc)

	switch p.Type {
	case PktIncompleteEOT, PktBadSequence:
		// simple mapping for the erratic error type
		var errName string
		switch p.ErrType {
		// Just map the basic ones that might have caused bad sequence, not strict since it's just formatting
		case PktD8:
			errName = "D8"
		case PktD16:
			errName = "D16"
		case PktD32:
			errName = "D32"
		case PktD64:
			errName = "D64"
		default:
			errName = fmt.Sprintf("%v", p.ErrType)
		}
		str += fmt.Sprintf("[%s]", errName)
	case PktVersion:
		str += fmt.Sprintf("; Ver=%d", p.Payload.D8)
	case PktFreq:
		str += fmt.Sprintf("; Freq=%dHz", p.Payload.D32)
	case PktTrig:
		str += fmt.Sprintf("; TrigData=0x%02X", p.Payload.D8)
	case PktM8:
		str += fmt.Sprintf("; Master=0x%02X", p.Master)
	case PktC8, PktC16:
		str += fmt.Sprintf("; Chan=0x%04X", p.Channel)
	case PktD4:
		str += fmt.Sprintf("; Data=0x%01X", p.Payload.D8&0xF)
	case PktD8:
		str += fmt.Sprintf("; Data=0x%02X", p.Payload.D8)
	case PktD16:
		str += fmt.Sprintf("; Data=0x%04X", p.Payload.D16)
	case PktD32:
		str += fmt.Sprintf("; Data=0x%08X", p.Payload.D32)
	case PktD64:
		str += fmt.Sprintf("; Data=0x%016X", p.Payload.D64)
	}

	if p.IsTSPkt() {
		str += fmt.Sprintf("; TS=0x%X ~[%d]", p.Timestamp, p.PktTSBits)
	}

	return str
}
