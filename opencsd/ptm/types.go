package ptm

import (
	"fmt"

	"opencsd/common"
)

// PacketType represents the type of PTM packet
type PacketType int

const (
	PacketTypeUnknown         PacketType = iota
	PacketTypeASYNC                      // A-Sync packet (0x00 x5 + 0x80)
	PacketTypeISYNC                      // I-Sync packet
	PacketTypeATOM                       // Atom packet
	PacketTypeBranchAddr                 // Branch address packet
	PacketTypeTimestamp                  // Timestamp packet
	PacketTypeWaypoint                   // Waypoint update packet
	PacketTypeContextID                  // Context ID packet (0x6E)
	PacketTypeVMID                       // VMID packet (0x3C)
	PacketTypeExceptionReturn            // Exception return packet (0x76)
)

func (t PacketType) String() string {
	switch t {
	case PacketTypeASYNC:
		return "ASYNC"
	case PacketTypeISYNC:
		return "ISYNC"
	case PacketTypeATOM:
		return "ATOM"
	case PacketTypeBranchAddr:
		return "BRANCH_ADDRESS"
	case PacketTypeTimestamp:
		return "TIMESTAMP"
	case PacketTypeWaypoint:
		return "WAYPOINT"
	case PacketTypeContextID:
		return "CONTEXT_ID"
	case PacketTypeVMID:
		return "VMID"
	case PacketTypeExceptionReturn:
		return "EXCEPTION_RETURN"
	default:
		return "UNKNOWN"
	}
}

// ISA type alias for common.ISA
type ISA = common.ISA

// ISA constants
const (
	ISAARM    = common.ISAARM
	ISAThumb2 = common.ISAThumb2
	ISATEE    = common.ISATEE
)

// ISyncReason represents why an I-Sync packet was generated
type ISyncReason int

const (
	ISyncPeriodic ISyncReason = iota
	ISyncTraceEnable
	ISyncAfterOverflow
	ISyncDebugExit
)

// Packet represents a decoded PTM packet
type Packet struct {
	Type   PacketType
	Data   []byte // Raw packet bytes
	Offset uint64 // Byte offset in trace stream

	// I-Sync specific fields
	Address     uint64
	ISA         ISA
	ISyncReason ISyncReason
	SecureState bool // S bit
	AltISA      bool
	Hypervisor  bool
	ContextID   uint32
	CycleCount  uint32
	VMID        uint8

	// Atom specific fields
	AtomBits  uint8 // E/N pattern
	AtomCount uint8 // Number of atoms

	// Timestamp specific fields
	Timestamp uint64 // Timestamp value

	// Branch Address specific fields
	ExceptionNum uint16
}

// Description returns a human-readable description of the packet
func (p *Packet) Description() string {
	switch p.Type {
	case PacketTypeASYNC:
		return "Alignment Synchronisation Packet"
	case PacketTypeISYNC:
		return fmt.Sprintf("Instruction Synchronisation packet; Addr=0x%x; %s; ISA=%s",
			p.Address, secureStr(p.SecureState), p.ISA)
	case PacketTypeATOM:
		return fmt.Sprintf("Atom packet; %s", atomPattern(p.AtomBits, p.AtomCount))
	case PacketTypeTimestamp:
		return fmt.Sprintf("Timestamp packet; TS=0x%x", p.Timestamp)
	case PacketTypeContextID:
		return fmt.Sprintf("Context ID packet; CtxtID=0x%08x", p.ContextID)
	case PacketTypeVMID:
		return fmt.Sprintf("VMID packet; VMID=0x%02x", p.VMID)
	case PacketTypeExceptionReturn:
		return "Exception Return packet"
	default:
		return "Unknown packet type"
	}
}

func secureStr(s bool) string {
	if s {
		return "S"
	}
	return "N"
}

func atomPattern(bits uint8, count uint8) string {
	if count == 0 {
		return ""
	}
	pattern := ""
	for i := uint8(0); i < count; i++ {
		if (bits & (1 << i)) != 0 {
			pattern += "E"
		} else {
			pattern += "N"
		}
	}
	return pattern
}

// Parse processes raw PTM trace data and returns packets
func (d *Decoder) Parse(raw []byte) ([]Packet, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var packets []Packet
	offset := uint64(0)

	for offset < uint64(len(raw)) {
		pkt, size, err := d.parseNextPacket(raw[offset:])
		if err != nil {
			return packets, err
		}
		if size == 0 {
			return packets, fmt.Errorf("parse stalled at offset %d", offset)
		}

		pkt.Offset = offset
		packets = append(packets, pkt)
		offset += uint64(size)
	}

	return packets, nil
}

// parseNextPacket extracts the next packet from the buffer
func (d *Decoder) parseNextPacket(buf []byte) (Packet, int, error) {
	if len(buf) == 0 {
		return Packet{}, 0, nil
	}

	header := buf[0]

	// Check for A-Sync: 0x00 0x00 0x00 0x00 0x00 0x80
	if len(buf) >= 6 &&
		buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 &&
		buf[3] == 0x00 && buf[4] == 0x00 && buf[5] == 0x80 {
		return Packet{
			Type: PacketTypeASYNC,
			Data: buf[0:6],
		}, 6, nil
	}

	// I-Sync: header = 0x08
	if header == 0x08 {
		return d.parseISync(buf)
	}

	// Timestamp: header = 0x42 or 0x46
	if header == 0x42 || header == 0x46 {
		return d.parseTimestamp(buf)
	}

	// Atom packets: bit 7 = 1, bit 0 = 0, excluding special cases
	// Must check before branch address to avoid misidentification
	if (header&0x80) != 0 && (header&0x01) == 0 {
		// Check if it's actually a branch address (bit 7=1, bit 0=1)
		// or if bits[6:1] indicate special encoding
		atomBits := (header >> 1) & 0x1F
		// If all bits 0 except bit 0, it's likely a branch address continuation
		if atomBits != 0 && atomBits != 0x1F {
			return d.parseAtom(buf)
		}
	}

	// Branch Address: bit 7 = 1, bit 0 = 1
	// OR bit 7 = 1, bit 0 = 0, bits[6:1] = all 0 (continuation byte)
	if (header&0x80) != 0 && ((header&0x01) != 0 || (header&0x7E) == 0) {
		return d.parseBranchAddress(buf)
	}

	// Context ID: header = 0x6E
	if header == 0x6E {
		return d.parseContextID(buf)
	}

	// VMID: header = 0x3C
	if header == 0x3C {
		return d.parseVMID(buf)
	}

	// Exception Return: header = 0x76
	if header == 0x76 {
		return d.parseExceptionReturn(buf)
	}

	// Unknown packet - consume one byte and continue
	return Packet{
		Type: PacketTypeUnknown,
		Data: buf[0:1],
	}, 1, nil
}

// parseISync parses an Instruction Synchronization packet
func (d *Decoder) parseISync(buf []byte) (Packet, int, error) {
	// I-Sync minimum: 6 bytes (header + 4 addr bytes + info byte)
	if len(buf) < 6 {
		return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
	}

	pkt := Packet{Type: PacketTypeISYNC}

	// Extract address (bytes 1-4, little endian)
	addr := uint64(buf[1]) | uint64(buf[2])<<8 | uint64(buf[3])<<16 | uint64(buf[4])<<24

	// Info byte (byte 5)
	info := buf[5]
	pkt.SecureState = (info & 0x08) != 0
	pkt.AltISA = (info & 0x04) != 0
	pkt.Hypervisor = (info & 0x02) != 0
	isyncReason := (info >> 5) & 0x3
	pkt.ISyncReason = ISyncReason(isyncReason)

	// Determine ISA from bit 0 of addr byte 1 and AltISA
	if (buf[1] & 0x01) != 0 {
		if pkt.AltISA {
			pkt.ISA = ISATEE
		} else {
			pkt.ISA = ISAThumb2
		}
	} else {
		pkt.ISA = ISAARM
	}

	// Clear LSB from address for alignment
	pkt.Address = addr & 0xFFFFFFFE

	size := 6
	pkt.Data = buf[0:size]

	// TODO: Parse optional cycle count and context ID bytes
	// For now, just return the basic 6-byte packet

	return pkt, size, nil
}

// parseTimestamp parses a Timestamp packet (header 0x42 or 0x46)
// Timestamp packets have variable length:
// - Header byte (0x42 or 0x46)
// - 1-8 timestamp bytes: bit 7 = continuation flag, bits[6:0] = data bits
// Each byte contributes 7 bits of the timestamp, shifted into position
func (d *Decoder) parseTimestamp(buf []byte) (Packet, int, error) {
	if len(buf) < 2 {
		return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
	}

	pkt := Packet{Type: PacketTypeTimestamp}
	size := 1
	tsVal := uint64(0)
	shift := 0

	// Read timestamp bytes until we find one without continuation bit
	maxBytes := 9 // Maximum 9 bytes for full 56-bit timestamp (7 bits per byte), index 1-9
	for size < len(buf) && size-1 < maxBytes {
		currByte := buf[size]

		// Extract 7 bits (bits 6:0)
		tsVal |= uint64(currByte&0x7F) << shift
		shift += 7
		size++

		// Check continuation bit (bit 7)
		if (currByte & 0x80) == 0 {
			// No continuation - we have the complete timestamp
			break
		}
	}

	pkt.Timestamp = tsVal
	pkt.Data = buf[0:size]

	return pkt, size, nil
}

// isAtomPacket checks if header byte indicates an atom packet
func (d *Decoder) isAtomPacket(header byte) bool {
	// Atom packets have specific bit patterns
	// Single atom: bit[7]=1, bit[0]=0, bits[6:1] = 000001 to 111110
	// P-header atoms: bits[7:6] = 10 or 11
	if (header&0x80) != 0 && (header&0x01) == 0 {
		// Could be single atom or multi-atom
		return true
	}
	return false
}

// parseAtom parses an Atom packet
func (d *Decoder) parseAtom(buf []byte) (Packet, int, error) {
	header := buf[0]
	pkt := Packet{Type: PacketTypeATOM, Data: buf[0:1]}

	// Simple atom encoding: single byte
	// bit 7 = 1, bit 0 = 0
	if (header&0x80) != 0 && (header&0x01) == 0 {
		// Extract atom from bits [6:1]
		payload := (header >> 1) & 0x3F

		// Find highest set bit (Stop Bit)
		stopBit := -1
		for i := 5; i >= 0; i-- {
			if (payload & (1 << i)) != 0 {
				stopBit = i
				break
			}
		}

		if stopBit == -1 {
			// No stop bit found, invalid
			return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
		}

		// Atoms are bits below stopBit
		count := uint8(stopBit)
		var atomPattern uint8

		// PTM: 0=E, 1=N. (OpenCSD seems to imply this matching PPL 0xd0 -> ENEEE)
		// We map 0->1 (E) and 1->0 (N) for common.AtomExecuted
		// LSB of atomPattern is Atom 0.
		// Atom 0 corresponds to bit below stopBit.
		for i := 0; i < int(count); i++ {
			bitPos := count - 1 - uint8(i)
			if (payload & (1 << bitPos)) == 0 {
				// 0 is Executed
				atomPattern |= (1 << i)
			}
		}

		pkt.AtomBits = atomPattern
		pkt.AtomCount = count
		return pkt, 1, nil
	}

	return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
}

// parseBranchAddress parses a Branch Address packet
func (d *Decoder) parseBranchAddress(buf []byte) (Packet, int, error) {
	// Branch address packets are variable length:
	// - 1-4 address bytes: bit 7 = 1 for continuation
	// - Optional 5th address byte (determines ISA)
	// - Optional exception/waypoint byte

	if len(buf) < 2 {
		return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
	}

	pkt := Packet{Type: PacketTypeBranchAddr}
	size := 1
	gotAllAddrBytes := false
	numAddrBytes := 1

	// Read address bytes (header + 1-4 address bytes)
	for size < len(buf) && !gotAllAddrBytes && numAddrBytes <= 5 {
		if numAddrBytes <= 4 {
			// Address bytes 1-4: check continuation bit
			if (buf[size-1] & 0x80) == 0 {
				// No continuation - we have all address bytes
				gotAllAddrBytes = true
				break
			}
			size++
			numAddrBytes++
		} else {
			// 5th address byte (if we get here, we had 4 continuation bytes)
			gotAllAddrBytes = true
			break
		}
	}

	// Check if there's an exception/waypoint byte
	// This exists if byte 5 has bit 6 set
	if numAddrBytes == 5 && size < len(buf) {
		if (buf[size-1] & 0x40) != 0 {
			size++
		}
	}

	pkt.Data = buf[0:size]
	// TODO: Extract actual address value and exception info

	return pkt, size, nil
}

// parseContextID parses a Context ID packet (header 0x6E)
// Context ID packets have variable length based on configuration:
// - Header byte (0x6E)
// - 0-4 bytes of context ID data (depends on configuration)
// For now, we parse up to 4 bytes to handle the maximum size
func (d *Decoder) parseContextID(buf []byte) (Packet, int, error) {
	// Minimum: just header (if ContextID size is 0)
	// Maximum: header + 4 bytes
	if len(buf) < 1 {
		return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
	}

	pkt := Packet{Type: PacketTypeContextID}

	// For simplicity, we'll try to read up to 4 bytes of context ID
	// In a full implementation, this should be based on the PTM configuration
	// For now, we read what's available up to 4 bytes
	size := 1
	ctxtID := uint32(0)
	numBytes := 0

	// Try to read up to 4 context ID bytes
	for size < len(buf) && numBytes < 4 {
		// Read context ID bytes (little endian)
		ctxtID |= uint32(buf[size]) << (numBytes * 8)
		size++
		numBytes++

		// Check if this looks like the start of another packet
		// We use a simple heuristic: if we've read at least 1 byte and
		// the next byte looks like a packet header, we stop
		if size < len(buf) && numBytes >= 1 {
			nextByte := buf[size]
			// Common packet headers: 0x00, 0x08, 0x42, 0x46, 0x6E, 0x3C, 0x76, 0x0C, 0x66
			// or high bit set for atoms/branches
			if nextByte == 0x00 || nextByte == 0x08 || nextByte == 0x42 ||
				nextByte == 0x46 || nextByte == 0x6E || nextByte == 0x3C ||
				nextByte == 0x76 || nextByte == 0x0C || nextByte == 0x66 {
				break
			}
		}
	}

	pkt.ContextID = ctxtID
	pkt.Data = buf[0:size]

	return pkt, size, nil
}

// parseVMID parses a VMID packet (header 0x3C)
// VMID packets have a fixed format:
// - Header byte (0x3C)
// - 1 payload byte containing the VMID value
func (d *Decoder) parseVMID(buf []byte) (Packet, int, error) {
	if len(buf) < 2 {
		return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
	}

	pkt := Packet{
		Type: PacketTypeVMID,
		VMID: buf[1],
		Data: buf[0:2],
	}

	return pkt, 2, nil
}

// parseExceptionReturn parses an Exception Return packet (header 0x76)
// Exception Return packets have a fixed format:
// - Header byte (0x76) only, no payload
func (d *Decoder) parseExceptionReturn(buf []byte) (Packet, int, error) {
	pkt := Packet{
		Type: PacketTypeExceptionReturn,
		Data: buf[0:1],
	}

	return pkt, 1, nil
}
