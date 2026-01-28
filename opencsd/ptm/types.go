package ptm

import "fmt"

// PacketType represents the type of PTM packet
type PacketType int

const (
	PacketTypeUnknown    PacketType = iota
	PacketTypeASYNC                 // A-Sync packet (0x00 x5 + 0x80)
	PacketTypeISYNC                 // I-Sync packet
	PacketTypeATOM                  // Atom packet
	PacketTypeBranchAddr            // Branch address packet
	PacketTypeTimestamp             // Timestamp packet
	PacketTypeWaypoint              // Waypoint update packet
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
	default:
		return "UNKNOWN"
	}
}

// ISA represents instruction set architecture
type ISA int

const (
	ISAARM ISA = iota
	ISAThumb2
	ISATEE
)

func (i ISA) String() string {
	switch i {
	case ISAARM:
		return "ARM(32)"
	case ISAThumb2:
		return "Thumb2"
	case ISATEE:
		return "TEE"
	default:
		return "Unknown"
	}
}

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
	Address      uint64
	ISA          ISA
	ISyncReason  ISyncReason
	SecureState  bool // S bit
	AltISA       bool
	Hypervisor   bool
	ContextID    uint32
	CycleCount   uint32

	// Atom specific fields
	AtomBits     uint8  // E/N pattern
	AtomCount    uint8  // Number of atoms

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

// Decoder handles PTM trace decoding
type Decoder struct {
	TraceID uint8
}

// NewDecoder creates a new PTM decoder for the given trace ID
func NewDecoder(traceID uint8) *Decoder {
	return &Decoder{TraceID: traceID}
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
		atomBits := (header >> 1) & 0x1F
		
		// Count number of atoms (find first 0 in atom pattern)
		count := uint8(0)
		for i := uint8(0); i < 5; i++ {
			if (atomBits & (1 << i)) != 0 {
				count++
			} else {
				break
			}
		}
		
		if count == 0 {
			count = 1 // At least one atom
		}
		
		pkt.AtomBits = atomBits & ((1 << count) - 1)
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
