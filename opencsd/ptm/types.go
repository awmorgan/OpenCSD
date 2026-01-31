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
	ISAValid    bool
	ISyncReason ISyncReason
	SecureState bool // Secure if true
	SecureValid bool
	AltISA      bool
	Hypervisor  bool
	ContextID   uint32
	CycleCount  uint32
	CCValid     bool // Cycle count is valid
	VMID        uint8
	AddrBits    uint8 // Number of valid address bits in Address

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

// extractCycleCount extracts a cycle count value from packet data.
// The first byte has continuation bit at 0x40 and data in bits[5:2].
// Subsequent bytes have continuation bit at 0x80 and data in bits[6:0].
// Returns the cycle count value and number of bytes consumed.
func extractCycleCount(buf []byte, offset int) (uint32, int) {
	if offset >= len(buf) {
		return 0, 0
	}

	cycleCount := uint32(0)
	byIdx := 0
	shift := 4 // First byte contributes 4 bits

	for {
		if offset+byIdx >= len(buf) {
			break
		}
		currByte := buf[offset+byIdx]

		if byIdx == 0 {
			// First byte: data in bits[5:2], cont bit at 0x40
			cycleCount = uint32((currByte >> 2) & 0x0F)
			if (currByte & 0x40) == 0 {
				// No continuation
				byIdx++
				break
			}
		} else {
			// Subsequent bytes: data in bits[6:0], cont bit at 0x80
			cycleCount |= uint32(currByte&0x7F) << shift
			shift += 7
			if (currByte&0x80) == 0 || byIdx >= 4 {
				// No continuation or max bytes reached
				byIdx++
				break
			}
		}
		byIdx++
	}

	return cycleCount, byIdx
}

// extractCycleCountFromTS extracts cycle count bytes that follow timestamp bytes.
// Uses the same format as extractCycleCount.
func extractCycleCountFromTS(buf []byte, offset int) (uint32, int) {
	return extractCycleCount(buf, offset)
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

	// Atom packets: bit 7 = 1, bit 0 = 0
	// Must check before branch address to avoid misidentification
	if (header&0x80) != 0 && (header&0x01) == 0 {
		return d.parseAtom(buf)
	}

	// Branch Address: bit 0 = 1 (all such headers)
	if (header & 0x01) != 0 {
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
	// Bit 3 is NS in PTM. Secure when NS bit is 0.
	pkt.SecureState = (info & 0x08) == 0
	pkt.SecureValid = true
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
	pkt.ISAValid = true

	// Clear LSB from address for alignment
	pkt.Address = addr & 0xFFFFFFFE

	size := 6

	// Parse optional cycle count if reason != periodic AND cycle accurate tracing is enabled
	// Since we don't always have config, try to parse if reason != 0 and there's more data
	if pkt.ISyncReason != ISyncPeriodic && d.CycleAccEnable && len(buf) > 6 {
		cc, ccBytes := extractCycleCount(buf, 6)
		if ccBytes > 0 {
			pkt.CycleCount = cc
			pkt.CCValid = true
			size += ccBytes
		}
	}

	pkt.Data = buf[0:size]

	return pkt, size, nil
}

// parseTimestamp parses a Timestamp packet (header 0x42 or 0x46)
// Timestamp packets have variable length:
// - Header byte (0x42 or 0x46)
// - 1-8 timestamp bytes: bit 7 = continuation flag, bits[6:0] = data bits
// Each byte contributes 7 bits of the timestamp, shifted into position
// - Optional cycle count bytes if cycle-accurate mode is enabled
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

	// In cycle-accurate mode, read cycle count bytes after timestamp
	if d.CycleAccEnable && size < len(buf) {
		cc, ccBytes := extractCycleCountFromTS(buf, size)
		if ccBytes > 0 {
			pkt.CycleCount = cc
			pkt.CCValid = true
			size += ccBytes
		}
	}

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

	// Atom packet encoding follows PTM P-header formats.
	if (header&0x80) != 0 && (header&0x01) == 0 {
		if d.CycleAccEnable {
			// Cycle-accurate atom: single atom with cycle count
			// Bit 1 (0x02): 0 = E (executed), 1 = N (not executed)
			pkt.AtomCount = 1
			if (header & 0x02) == 0 {
				pkt.AtomBits = 1 // E
			} else {
				pkt.AtomBits = 0 // N
			}

			size := 1

			// If bit 6 (0x40) is set, there are cycle count bytes
			if (header & 0x40) != 0 {
				cc, ccBytes := extractCycleCount(buf, 0)
				if ccBytes > 0 {
					pkt.CycleCount = cc
					pkt.CCValid = true
					size = ccBytes
				}
			} else {
				// No continuation - cycle count comes from header only
				// Extract from bits 5:2 of header
				pkt.CycleCount = uint32((header >> 2) & 0x0F)
				pkt.CCValid = true
			}

			pkt.Data = buf[0:size]
			return pkt, size, nil
		} else {
			// Non-cycle-accurate: parse multiple atoms from header
			atomCount, atomBits := parseAtomFromHeader(header)
			if atomCount == 0 {
				return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
			}
			pkt.AtomBits = atomBits
			pkt.AtomCount = atomCount
			return pkt, 1, nil
		}
	}

	return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
}

// parseBranchAddress parses a Branch Address packet
func (d *Decoder) parseBranchAddress(buf []byte) (Packet, int, error) {
	// Branch address packets are variable length:
	// - 1-4 address bytes: bit 7 = 1 for continuation
	// - Optional 5th address byte (determines ISA)
	// - Optional exception bytes

	if len(buf) < 1 {
		return Packet{Type: PacketTypeUnknown, Data: buf[0:1]}, 1, nil
	}

	pkt := Packet{Type: PacketTypeBranchAddr}
	size := 1
	numAddrBytes := 1
	gotAddrBytes := false
	gotExcepBytes := false
	addrPktISA, hasISA := ISAARM, false
	var lastAddrByte byte = buf[0]

	if (buf[0] & 0x80) == 0 {
		gotAddrBytes = true
		gotExcepBytes = true
	}

	for size < len(buf) && !gotAddrBytes && numAddrBytes <= 5 {
		curr := buf[size]
		lastAddrByte = curr
		size++
		numAddrBytes++

		if numAddrBytes < 5 {
			if (curr & 0x80) == 0 {
				gotAddrBytes = true
				if (curr & 0x40) == 0 {
					gotExcepBytes = true
				}
			}
		} else {
			// 5th address byte determines ISA
			gotAddrBytes = true
			if (curr & 0x40) == 0 {
				gotExcepBytes = true
			}

			addrPktISA = ISAARM
			hasISA = true
			if (curr & 0x20) == 0x20 {
				// Jazelle not represented in Go ISA; keep ARM for now.
				addrPktISA = ISAARM
			} else if (curr & 0x30) == 0x10 {
				addrPktISA = ISAThumb2
			}
		}
	}

	// Exception bytes
	if gotAddrBytes && !gotExcepBytes && size < len(buf) {
		if (lastAddrByte & 0x40) != 0 {
			// Read exception bytes
			E1 := buf[size]
			size++
			excepAltISA := (E1 & 0x40) != 0
			pkt.SecureState = (E1 & 0x01) == 0
			pkt.SecureValid = true
			exNum := uint16((E1 >> 1) & 0x0F)
			if (E1&0x80) != 0 && size < len(buf) {
				E2 := buf[size]
				size++
				pkt.Hypervisor = ((E2 >> 5) & 0x1) != 0
				exNum |= uint16(E2&0x1F) << 4
			}
			pkt.ExceptionNum = exNum
			gotExcepBytes = true

			// Adjust ISA for exception alt ISA if applicable
			if addrPktISA == ISATEE && !excepAltISA {
				addrPktISA = ISAThumb2
			} else if addrPktISA == ISAThumb2 && excepAltISA {
				addrPktISA = ISATEE
			}
		}
	}

	// Extract address bits
	addrVal, addrBits := extractBranchAddressBits(buf, numAddrBytes, addrPktISA)
	pkt.Address = addrVal
	pkt.AddrBits = addrBits
	if hasISA {
		pkt.ISA = addrPktISA
		pkt.ISAValid = true
	}

	// Parse optional cycle count if enabled
	if d.CycleAccEnable && gotExcepBytes && size < len(buf) {
		cc, ccBytes := extractCycleCount(buf, size)
		if ccBytes > 0 {
			pkt.CycleCount = cc
			pkt.CCValid = true
			size += ccBytes
		}
	}

	pkt.Data = buf[0:size]
	return pkt, size, nil
}

func parseAtomFromHeader(pHdr byte) (uint8, uint8) {
	var atomNum uint8
	atomFmtID := pHdr & 0xF0
	if atomFmtID == 0x80 {
		if (pHdr & 0x08) == 0x08 {
			atomNum = 2
		} else {
			atomNum = 1
		}
	} else if atomFmtID == 0x90 {
		atomNum = 3
	} else {
		if (pHdr & 0xE0) == 0xA0 {
			atomNum = 4
		} else {
			atomNum = 5
		}
	}

	if atomNum == 0 {
		return 0, 0
	}

	atomMask := byte(0x2)
	var atomBits uint8
	for i := uint8(0); i < atomNum; i++ {
		atomBits <<= 1
		if (pHdr & atomMask) == 0 {
			atomBits |= 0x1
		}
		atomMask <<= 1
	}

	return atomNum, atomBits
}

func extractBranchAddressBits(buf []byte, numAddrBytes int, isa ISA) (uint64, uint8) {
	if numAddrBytes == 0 {
		return 0, 0
	}
	addrVal := uint64(0)
	mask := byte(0x7E)
	numBits := uint8(7)
	shift := 0
	nextShift := 0
	var totalBits uint8

	for i := 0; i < numAddrBytes; i++ {
		if i == 4 {
			mask = 0x0F
			numBits = 4
			if isa == ISAARM {
				mask = 0x07
				numBits = 3
			}
		} else if i > 0 {
			mask = 0x7F
			numBits = 7
			if i == numAddrBytes-1 {
				mask = 0x3F
				numBits = 6
			}
		}

		shift = nextShift
		addrVal |= uint64(buf[i]&mask) << shift
		totalBits += numBits

		if i == 0 {
			nextShift = 7
		} else {
			nextShift += 7
		}
	}

	if isa == ISAARM {
		addrVal <<= 1
		totalBits++
	}

	return addrVal, totalBits
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
