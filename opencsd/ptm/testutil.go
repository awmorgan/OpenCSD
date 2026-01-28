package ptm

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// CppPacket represents a packet entry from C++ .ppl output
type CppPacket struct {
	ByteOffset uint64 // Idx value
	TraceID    uint8  // ID value
	Bytes      []byte // Hex bytes from packet
	Type       string // Packet type (ASYNC, ISYNC, ATOM, etc.)
	Desc       string // Full description
}

// LoadCppReference parses a .ppl file and extracts packet information
// for the specified trace ID
func LoadCppReference(pplPath string, traceID uint8) ([]CppPacket, error) {
	file, err := os.Open(pplPath)
	if err != nil {
		return nil, fmt.Errorf("open ppl file: %w", err)
	}
	defer file.Close()

	// Pattern: Idx:26565; ID:13; [0x00 0x00 0x00 0x00 0x00 0x80 ];	ASYNC : Alignment Synchronisation Packet;
	pktPattern := regexp.MustCompile(`^Idx:(\d+);\s+ID:(\d+);\s+\[(.*?)\]\s*;\s+(\w+)\s*:\s*(.*)$`)

	var packets []CppPacket
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		matches := pktPattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		id, _ := strconv.ParseUint(matches[2], 10, 8)
		if uint8(id) != traceID {
			continue // Skip packets from other trace IDs
		}

		offset, _ := strconv.ParseUint(matches[1], 10, 64)
		hexBytes := parseHexBytes(matches[3])
		pktType := matches[4]
		desc := matches[5]

		packets = append(packets, CppPacket{
			ByteOffset: offset,
			TraceID:    uint8(id),
			Bytes:      hexBytes,
			Type:       pktType,
			Desc:       desc,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan ppl file: %w", err)
	}

	return packets, nil
}

// parseHexBytes converts "0x00 0x00 0x00 0x00 0x00 0x80" to []byte
func parseHexBytes(hexStr string) []byte {
	parts := strings.Fields(hexStr)
	bytes := make([]byte, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimPrefix(part, "0x")
		if part == "" {
			continue
		}
		val, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			continue
		}
		bytes = append(bytes, byte(val))
	}

	return bytes
}

// FormatPPL generates .ppl-style output for a packet
func FormatPPL(pkt *Packet, offset uint64, traceID uint8) string {
	// Format hex bytes
	hexParts := make([]string, len(pkt.Data))
	for i, b := range pkt.Data {
		hexParts[i] = fmt.Sprintf("0x%02x", b)
	}
	hexStr := strings.Join(hexParts, " ")

	// Generate output line
	return fmt.Sprintf("Idx:%d; ID:%d; [%s ];\t%s : %s",
		offset, traceID, hexStr, pkt.Type, pkt.Description())
}
