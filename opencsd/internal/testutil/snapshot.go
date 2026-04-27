package testutil

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"opencsd/internal/snapshot"
)

type snapshotLine struct {
	line  string
	id    string
	idx   int
	order int
}

// SanitizePPL filters and normalizes PPL output lines for diff comparison.
func SanitizePPL(s string, traceIDs []string) string {
	lines := strings.Split(normalizeNewlines(s), "\n")
	parsed := parseSnapshotLines(lines[firstRecordLine(lines):])
	sortSnapshotLines(parsed)

	return joinSnapshotLines(parsed, traceIDSet(traceIDs))
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func traceIDSet(traceIDs []string) map[string]struct{} {
	if len(traceIDs) == 0 {
		return nil
	}

	ids := make(map[string]struct{}, len(traceIDs))
	for _, id := range traceIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			ids[id] = struct{}{}
		}
	}
	return ids
}

func firstRecordLine(lines []string) int {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Idx:") || strings.HasPrefix(trimmed, "Frame:") {
			return i
		}
	}
	return 0
}

func parseSnapshotLines(lines []string) []snapshotLine {
	parsed := make([]snapshotLine, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, record := range SplitIdxRecords(line) {
			if parsedLine, ok := parseSnapshotLine(record, len(parsed)); ok {
				parsed = append(parsed, parsedLine)
			}
		}
	}
	return parsed
}

func parseSnapshotLine(line string, order int) (snapshotLine, bool) {
	normalized := NormalizeSnapshotLine(line)
	if normalized == "" {
		return snapshotLine{}, false
	}

	id, ok := ExtractLineID(line)
	if !ok {
		return snapshotLine{}, false
	}

	idx, ok := ExtractLineIdx(line)
	if !ok {
		return snapshotLine{}, false
	}

	return snapshotLine{line: normalized, id: id, idx: idx, order: order}, true
}

func sortSnapshotLines(lines []snapshotLine) {
	slices.SortStableFunc(lines, func(a, b snapshotLine) int {
		switch {
		case a.idx < b.idx:
			return -1
		case a.idx > b.idx:
			return 1
		case a.id < b.id:
			return -1
		case a.id > b.id:
			return 1
		case a.order < b.order:
			return -1
		case a.order > b.order:
			return 1
		default:
			return 0
		}
	})
}

func joinSnapshotLines(lines []snapshotLine, ids map[string]struct{}) string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(ids) == 0 || hasTraceID(ids, line.id) {
			out = append(out, line.line)
		}
	}
	return strings.Join(out, "\n")
}

func hasTraceID(ids map[string]struct{}, id string) bool {
	_, ok := ids[id]
	return ok
}

func SplitIdxRecords(line string) []string {
	var records []string
	for {
		start := strings.Index(line, "Idx:")
		if start < 0 {
			return records
		}
		line = line[start:]

		next := strings.Index(line[len("Idx:"):], "Idx:")
		if next < 0 {
			return appendRecord(records, line)
		}

		end := len("Idx:") + next
		records = appendRecord(records, line[:end])
		line = line[end:]
	}
}

func appendRecord(records []string, record string) []string {
	record = strings.TrimSpace(record)
	if strings.HasPrefix(record, "Idx:") {
		return append(records, record)
	}
	return records
}

func NormalizeSnapshotLine(line string) string {
	if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
		return line
	}

	left, right, ok := strings.Cut(line, "\t")
	if !ok {
		return ""
	}

	packetType := ExtractPacketType(right)
	if packetType == "" {
		return ""
	}
	return strings.TrimSpace(left) + "\t" + packetType
}

func ExtractPacketType(s string) string {
	before, _, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(before)
}

func FirstDiff(got, want []string) (int, string, string) {
	maxLen := max(len(want), len(got))
	for i := range maxLen {
		gotLine, wantLine := lineAt(got, i), lineAt(want, i)
		if gotLine != wantLine {
			return i + 1, gotLine, wantLine
		}
	}
	return 0, "", ""
}

func lineAt(lines []string, i int) string {
	if i >= len(lines) {
		return ""
	}
	return lines[i]
}

func FindParsedDeviceByName(devs map[string]*snapshot.Device, name string) *snapshot.Device {
	for _, dev := range devs {
		if dev != nil && dev.Name == name {
			return dev
		}
	}
	return nil
}

func parseHexOrDecErr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse integer string %q: %w", s, err)
	}
	return v, nil
}

func ParseHexOrDec(s string) uint64 {
	v, err := parseHexOrDecErr(s)
	if err != nil {
		return 0
	}
	return v
}

func ExtractLineID(line string) (string, bool) {
	id, ok := extractDelimitedField(line, "ID:")
	if !ok {
		return "", false
	}
	return strings.ToLower(id), true
}

func ExtractLineIdx(line string) (int, bool) {
	field, ok := extractDelimitedField(line, "Idx:")
	if !ok {
		return 0, false
	}

	idx, err := strconv.Atoi(field)
	if err != nil {
		return 0, false
	}
	return idx, true
}

func extractDelimitedField(line, prefix string) (string, bool) {
	_, after, ok := strings.Cut(line, prefix)
	if !ok {
		return "", false
	}

	before, _, ok := strings.Cut(after, ";")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(before), true
}
