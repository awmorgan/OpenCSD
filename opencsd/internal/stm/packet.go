package stm

import (
	"fmt"
	"strings"

	"opencsd/internal/ocsd"
)

// PktType represents STM protocol packet types.
// Contains both protocol packet types and markers for unsynced processor state
// and bad packet sequences.
type PktType int

const (
	// markers for unknown packets / state
	PktNotSync       PktType = iota // Not synchronised
	PktIncompleteEOT                // Incomplete packet flushed at end of trace.

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
	Index    ocsd.TrcIndex
	Type     PktType
	OrigType PktType

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
}

// ResetStartState initializes packet state at start of decoder.
func (p *Packet) ResetStartState() {
	p.Master = 0
	p.Channel = 0
	p.Timestamp = 0
	p.TSType = TSUnknown
	p.Type = PktNotSync
	p.OrigType = PktNotSync
	p.ResetNextPacket()
}

// ResetNextPacket initializes state for the next packet.
func (p *Packet) ResetNextPacket() {
	p.OrigType = p.Type
	p.PktTSBits = 0
	p.PktHasMarker = 0
	p.PktHasTS = 0
}

func flagFromBool(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func (p *Packet) SetPacketType(typ PktType, bMarker bool) {
	p.Type = typ
	p.PktHasMarker = flagFromBool(bMarker)
}

func (p *Packet) SetMaster(master uint8) {
	p.Master = master
	p.Channel = 0 // M8 forces current channel to 0
}

func (p *Packet) SetChannel(channel uint16, b8Bit bool) {
	if b8Bit {
		p.Channel = (p.Channel & 0xFF00) | (channel & 0xFF)
		return
	}
	p.Channel = channel
}

func (p *Packet) SetTS(tsVal uint64, updatedBits uint8) {
	if updatedBits == 64 {
		p.Timestamp = tsVal
	} else {
		mask := (uint64(1) << updatedBits) - 1
		p.Timestamp = (p.Timestamp &^ mask) | (tsVal & mask)
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

func (p *Packet) IsMarkerPkt() bool { return p.PktHasMarker != 0 }

func (p *Packet) IsTSPkt() bool { return p.PktHasTS != 0 }

func (p *Packet) IsBadPacket() bool {
	switch p.Type {
	case PktIncompleteEOT, PktBadSequence, PktReserved:
		return true
	default:
		return false
	}
}

type pktTypeInfo struct {
	name       string
	desc       string
	markerInfo bool
}

var pktTypeInfos = [...]pktTypeInfo{
	PktNotSync:       {"NOTSYNC", "STM not synchronised", false},
	PktIncompleteEOT: {"INCOMPLETE_EOT", "Incomplete packet flushed at end of trace", false},
	PktAsync:         {"ASYNC", "Alignment synchronisation packet", false},
	PktVersion:       {"VERSION", "Version packet", false},
	PktFreq:          {"FREQ", "Frequency packet", false},
	PktNull:          {"NULL", "Null packet", false},
	PktTrig:          {"TRIG", "Trigger packet", true},
	PktGErr:          {"GERR", "Global Error", false},
	PktMErr:          {"MERR", "Master Error", false},
	PktM8:            {"M8", "Set current master", false},
	PktC8:            {"C8", "Set current channel", false},
	PktC16:           {"C16", "Set current channel", false},
	PktFlag:          {"FLAG", "Flag packet", true},
	PktD4:            {"D4", "4 bit data", true},
	PktD8:            {"D8", "8 bit data", true},
	PktD16:           {"D16", "16 bit data", true},
	PktD32:           {"D32", "32 bit data", true},
	PktD64:           {"D64", "64 bit data", true},
	PktBadSequence:   {"BAD_SEQUENCE", "Invalid sequence in packet", false},
	PktReserved:      {"RESERVED", "Reserved Packet Header", false},
}

var unknownPktTypeInfo = pktTypeInfo{"UNKNOWN", "ERROR: unknown packet type", false}

func packetInfo(pktType PktType) pktTypeInfo {
	if pktType >= 0 && int(pktType) < len(pktTypeInfos) {
		info := pktTypeInfos[pktType]
		if info.name != "" {
			return info
		}
	}
	return unknownPktTypeInfo
}

func (p *Packet) pktTypeName(pktType PktType) string {
	return packetInfo(pktType).name
}

func (p *Packet) String() string {
	var sb strings.Builder
	info := packetInfo(p.Type)

	sb.WriteString(info.name)
	if info.markerInfo {
		p.writeMarkerTSSuffix(&sb)
	}
	sb.WriteString(":")
	sb.WriteString(info.desc)
	if info.markerInfo {
		p.writeMarkerTSDescription(&sb)
	}

	p.writePayloadDescription(&sb)
	p.writeTimestampDescription(&sb)
	return sb.String()
}

func (p *Packet) writeMarkerTSSuffix(sb *strings.Builder) {
	if p.IsMarkerPkt() {
		sb.WriteString("M")
	}
	if p.IsTSPkt() {
		sb.WriteString("TS")
	}
}

func (p *Packet) writeMarkerTSDescription(sb *strings.Builder) {
	if p.IsMarkerPkt() {
		sb.WriteString(" + marker")
	}
	if p.IsTSPkt() {
		sb.WriteString(" + timestamp")
	}
}

func (p *Packet) writePayloadDescription(sb *strings.Builder) {
	switch p.Type {
	case PktIncompleteEOT, PktBadSequence:
		fmt.Fprintf(sb, "[%s]", p.pktTypeName(p.OrigType))
	case PktVersion:
		fmt.Fprintf(sb, "; Ver=%d", p.Payload.D8)
	case PktFreq:
		fmt.Fprintf(sb, "; Freq=%dHz", p.Payload.D32)
	case PktTrig:
		fmt.Fprintf(sb, "; TrigData=0x%02x", p.Payload.D8)
	case PktM8:
		fmt.Fprintf(sb, "; Master=0x%02x", p.Master)
	case PktC8, PktC16:
		fmt.Fprintf(sb, "; Chan=0x%04x", p.Channel)
	case PktD4:
		fmt.Fprintf(sb, "; Data=0x%01x", p.Payload.D8&0xF)
	case PktD8:
		fmt.Fprintf(sb, "; Data=0x%02x", p.Payload.D8)
	case PktD16:
		fmt.Fprintf(sb, "; Data=0x%04x", p.Payload.D16)
	case PktD32:
		fmt.Fprintf(sb, "; Data=0x%08x", p.Payload.D32)
	case PktD64:
		fmt.Fprintf(sb, "; Data=0x%016x", p.Payload.D64)
	}
}

func (p *Packet) writeTimestampDescription(sb *strings.Builder) {
	if !p.IsTSPkt() {
		return
	}
	updateMask := timestampUpdateMask(p.PktTSBits)
	fmt.Fprintf(sb, "; TS=0x%016X ~[0x%X]", p.Timestamp, p.Timestamp&updateMask)
}

func timestampUpdateMask(bits uint8) uint64 {
	switch {
	case bits >= 64:
		return ^uint64(0)
	case bits == 0:
		return 0
	default:
		return (uint64(1) << bits) - 1
	}
}
