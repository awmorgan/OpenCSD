package helpers

import (
	"bufio"
	"os"
	"regexp"
)

// PPLRecordKind distinguishes between raw packet and generic element lines.
type PPLRecordKind string

const (
	PPLRecordPacket  PPLRecordKind = "packet"
	PPLRecordElement PPLRecordKind = "element"
)

// PPLRecord represents a single packet or element line from a PPL file.
type PPLRecord struct {
	Index       string        // Idx value
	ID          string        // Trace ID string (hex without 0x)
	Kind        PPLRecordKind // packet or element
	Line        string        // Full original line
	PacketType  string        // Packet type (if packet line)
	ElemType    string        // Element type (if element line)
	ElemContent string        // Element content without outer parens (if element line)
}

// LoadPPLRecords parses a .ppl file and returns packet/element lines in file order.
func LoadPPLRecords(path string) ([]PPLRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []PPLRecord
	scanner := bufio.NewScanner(file)

	packetRe := regexp.MustCompile(`^Idx:(\d+); ID:([0-9a-fA-F]+); \[(.*)\];\s*(\w+)\s*:\s*(.*)$`)
	elemRe := regexp.MustCompile(`^Idx:(\d+); ID:([0-9a-fA-F]+); (OCSD_GEN_TRC_ELEM_\w+)\((.*)\)\s*$`)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		if matches := packetRe.FindStringSubmatch(line); len(matches) == 6 {
			records = append(records, PPLRecord{
				Index:      matches[1],
				ID:         matches[2],
				Kind:       PPLRecordPacket,
				Line:       line,
				PacketType: matches[4],
			})
			continue
		}

		if matches := elemRe.FindStringSubmatch(line); len(matches) == 5 {
			records = append(records, PPLRecord{
				Index:       matches[1],
				ID:          matches[2],
				Kind:        PPLRecordElement,
				Line:        line,
				ElemType:    matches[3],
				ElemContent: matches[4],
			})
			continue
		}
	}

	return records, scanner.Err()
}
