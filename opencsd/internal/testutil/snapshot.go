package testutil

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"opencsd/internal/snapshot"
)

// SanitizePPL filters and normalizes PPL output lines for diff comparison.
func SanitizePPL(s string, traceIDs []string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")

	idSet := make(map[string]struct{}, len(traceIDs))
	for _, id := range traceIDs {
		idSet[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
	}

	start := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Idx:") || strings.HasPrefix(trimmed, "Frame:") {
			start = i
			break
		}
	}

	type parsedLine struct {
		line  string
		id    string
		idx   int
		order int
	}

	parsed := make([]parsedLine, 0, len(lines)-start)
	ord := 0
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, idxLine := range SplitIdxRecords(line) {
			normalized := NormalizeSnapshotLine(idxLine)
			if normalized == "" {
				continue
			}
			idVal, ok := ExtractLineID(idxLine)
			if !ok {
				continue
			}
			idxVal, ok := ExtractLineIdx(idxLine)
			if !ok {
				continue
			}
			parsed = append(parsed, parsedLine{line: normalized, id: idVal, idx: idxVal, order: ord})
			ord++
		}
	}

	sort.SliceStable(parsed, func(i, j int) bool {
		if parsed[i].idx != parsed[j].idx {
			return parsed[i].idx < parsed[j].idx
		}
		if parsed[i].id != parsed[j].id {
			return parsed[i].id < parsed[j].id
		}
		return parsed[i].order < parsed[j].order
	})

	if len(idSet) == 0 {
		out := make([]string, 0, len(parsed))
		for _, entry := range parsed {
			out = append(out, entry.line)
		}
		return strings.Join(out, "\n")
	}

	out := make([]string, 0, len(parsed))
	for _, entry := range parsed {
		if _, ok := idSet[entry.id]; ok {
			out = append(out, entry.line)
		}
	}

	return strings.Join(out, "\n")
}

func SplitIdxRecords(line string) []string {
	if !strings.Contains(line, "Idx:") {
		return nil
	}
	starts := make([]int, 0, 2)
	for pos := 0; pos < len(line); {
		i := strings.Index(line[pos:], "Idx:")
		if i < 0 {
			break
		}
		starts = append(starts, pos+i)
		pos += i + len("Idx:")
	}
	if len(starts) == 0 {
		return nil
	}
	records := make([]string, 0, len(starts))
	for i, st := range starts {
		end := len(line)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		rec := strings.TrimSpace(line[st:end])
		if strings.HasPrefix(rec, "Idx:") {
			records = append(records, rec)
		}
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
	packetType := ExtractPacketType(strings.TrimSpace(right))
	if packetType == "" {
		return ""
	}
	return strings.TrimSpace(left) + "\t" + packetType
}

func ExtractPacketType(s string) string {
	if s == "" {
		return ""
	}
	before, _, ok := strings.Cut(s, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(before)
}

func FirstDiff(got, want []string) (int, string, string) {
	maxLen := max(len(want), len(got))
	for i := range maxLen {
		var gotLine, wantLine string
		if i < len(got) {
			gotLine = got[i]
		}
		if i < len(want) {
			wantLine = want[i]
		}
		if gotLine != wantLine {
			return i + 1, gotLine, wantLine
		}
	}
	return 0, "", ""
}

func FindParsedDeviceByName(devs map[string]*snapshot.ParsedDevice, name string) *snapshot.ParsedDevice {
	for _, dev := range devs {
		if dev != nil && dev.DeviceName == name {
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
	_, after, ok := strings.Cut(line, "ID:")
	if !ok {
		return "", false
	}
	rest := after
	before, _, ok := strings.Cut(rest, ";")
	if !ok {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(before)), true
}

func ExtractLineIdx(line string) (int, bool) {
	_, after, ok := strings.Cut(line, "Idx:")
	if !ok {
		return 0, false
	}
	before, _, ok := strings.Cut(after, ";")
	if !ok {
		return 0, false
	}
	idx, err := strconv.Atoi(strings.TrimSpace(before))
	if err != nil {
		return 0, false
	}
	return idx, true
}
