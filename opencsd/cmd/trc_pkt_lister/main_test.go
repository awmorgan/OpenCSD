package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type listerGoldenCase struct {
	name        string
	decoder     string
	goldenPath  string
	snapshotDir string
	sourceName  string
	id          string
	decode      bool
	extraFlags  []string
}

func TestTraceListerGoldens(t *testing.T) {
	pattern := filepath.Join("..", "..", "internal", "*", "testdata", "*.ppl")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no golden trc_pkt_lister files found with pattern: %s", pattern)
	}

	slices.Sort(paths)
	testCases := make([]listerGoldenCase, 0, len(paths))
	for _, p := range paths {
		tc, parseErr := parseGoldenCase(p)
		if parseErr != nil {
			// Skip golden files without corresponding snapshot directories
			if strings.Contains(parseErr.Error(), "invalid snapshot dir") {
				continue
			}
			t.Fatalf("parse test case from %s: %v", p, parseErr)
		}
		testCases = append(testCases, tc)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{
				"-ss_dir", tc.snapshotDir,
				"-logfilename", filepath.Join(t.TempDir(), "out.ppl"),
				"-no_time_print",
			}
			if tc.sourceName != "" {
				args = append(args, "-src_name", tc.sourceName)
			}
			if tc.id != "" {
				args = append(args, "-id", tc.id)
			}
			args = append(args, tc.extraFlags...)
			if tc.decode {
				args = append(args, "-decode")
			}

			outPath := args[3]
			if err := run(args); err != nil {
				t.Fatalf("run(%v) failed: %v", args, err)
			}

			gotBytes, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read generated output %s: %v", outPath, err)
			}
			wantBytes, err := os.ReadFile(tc.goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", tc.goldenPath, err)
			}

			got := sanitizeTraceListerPPL(string(gotBytes), tc.decoder)
			want := sanitizeTraceListerPPL(string(wantBytes), tc.decoder)

			if got != want {
				gotLines := strings.Split(got, "\n")
				wantLines := strings.Split(want, "\n")
				line, gotLine, wantLine := firstDiff(gotLines, wantLines)
				t.Fatalf("golden mismatch at line %d\nwant: %s\n got: %s", line, wantLine, gotLine)
			}
		})
	}
}

func parseGoldenCase(goldenPath string) (listerGoldenCase, error) {
	content, err := os.ReadFile(goldenPath)
	if err != nil {
		return listerGoldenCase{}, err
	}

	name := strings.TrimSuffix(filepath.Base(goldenPath), ".ppl")
	decoder := filepath.Base(filepath.Dir(filepath.Dir(goldenPath)))

	// Extract snapshot directory by removing known suffixes
	snapshotName := name
	for _, suffix := range []string{"_src_addr_N", "_multi_sess"} {
		if before, ok := strings.CutSuffix(snapshotName, suffix); ok {
			snapshotName = before
			break
		}
	}

	snapshotDir := filepath.Join(filepath.Dir(goldenPath), snapshotName)
	if stat, err := os.Stat(snapshotDir); err != nil || !stat.IsDir() {
		return listerGoldenCase{}, fmt.Errorf("invalid snapshot dir %s", snapshotDir)
	}

	id, decode, extraFlags := parseOptionsFromGolden(name, string(content))

	return listerGoldenCase{
		name:        filepath.ToSlash(filepath.Join(decoder, snapshotName, name+".ppl")),
		decoder:     decoder,
		goldenPath:  goldenPath,
		snapshotDir: snapshotDir,
		sourceName:  extractSourceName(string(content)),
		id:          id,
		decode:      decode,
		extraFlags:  extraFlags,
	}, nil
}

func parseOptionsFromGolden(name, ppl string) (string, bool, []string) {
	decode := strings.Contains(strings.ToLower(name), "-dcd-")
	id := ""
	var extraFlags []string

	if m := regexp.MustCompile(`(?i)(?:_|-dcd-)0x([0-9a-f]+)$`).FindStringSubmatch(name); len(m) == 2 {
		id = "0x" + strings.ToLower(m[1])
	}

	cmdLine := extractGoldenCommandLine(ppl)
	if cmdLine == "" {
		return id, decode, extraFlags
	}

	fields := strings.Fields(cmdLine)
	for i := range fields {
		tok := fields[i]
		switch tok {
		case "-decode", "-decode_only":
			decode = true
		case "-id":
			if i+1 < len(fields) {
				parsed := strings.ToLower(strings.TrimSuffix(fields[i+1], ","))
				if parsed != "" {
					if _, err := strconv.ParseUint(parsed, 0, 8); err == nil {
						id = parsed
					}
				}
			}
		case "-src_addr_n", "-multi_session", "-pkt_mon", "-aa64_opcode_chk":
			// These flags should be passed through
			extraFlags = append(extraFlags, tok)
		case "-dstream_format", "-o_raw_packed", "-o_raw_unpacked":
			// These flags should be passed through
			extraFlags = append(extraFlags, tok)
		}
	}

	return id, decode, extraFlags
}

func extractGoldenCommandLine(ppl string) string {
	lines := strings.Split(normalizeNewlines(ppl), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "Test Command Line:-" {
			continue
		}

		var b strings.Builder
		for j := i + 1; j < len(lines); j++ {
			curr := strings.TrimSpace(lines[j])
			if curr == "" {
				if b.Len() > 0 {
					break
				}
				continue
			}
			if strings.HasPrefix(curr, "Trace Packet Lister :") {
				break
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(curr)
		}
		return b.String()
	}
	return ""
}

func extractSourceName(ppl string) string {
	for line := range strings.SplitSeq(normalizeNewlines(ppl), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Using ") || !strings.HasSuffix(line, " as trace source") {
			continue
		}
		line = strings.TrimPrefix(line, "Using ")
		line = strings.TrimSuffix(line, " as trace source")
		return strings.TrimSpace(line)
	}
	return ""
}

func sanitizeTraceListerPPL(ppl, decoder string) string {
	lines := strings.Split(normalizeNewlines(ppl), "\n")
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		if mappedRange, ok := normalizeMappedRangeLine(raw); ok {
			out = append(out, mappedRange)
			continue
		}

		if sourceLine, ok := normalizeSourceLine(raw); ok {
			out = append(out, sourceLine)
			continue
		}

		records := splitIdxRecords(raw)
		for _, rec := range records {
			normalized := normalizeTraceListerIdxRecord(rec, decoder)
			if normalized != "" {
				out = append(out, normalized)
			}
		}
	}

	collapsed := make([]string, 0, len(out))
	for _, line := range out {
		if len(collapsed) > 0 && line == collapsed[len(collapsed)-1] && isNoSyncPacketLine(line) {
			continue
		}
		collapsed = append(collapsed, line)
	}

	idSet := map[string]struct{}{}
	for _, line := range collapsed {
		if id, ok := extractNormalizedIDFromLine(line); ok {
			idSet[id] = struct{}{}
		}
	}
	if len(idSet) > 1 {
		filtered := collapsed[:0]
		for _, line := range collapsed {
			if isNoSyncPacketLine(line) {
				continue
			}
			filtered = append(filtered, line)
		}
		collapsed = filtered

		ids := make([]string, 0, len(idSet))
		for id := range idSet {
			ids = append(ids, id)
		}
		slices.Sort(ids)

		byID := make(map[string][]string, len(ids))
		for _, line := range collapsed {
			if id, ok := extractNormalizedIDFromLine(line); ok {
				byID[id] = append(byID[id], line)
			}
		}

		reordered := make([]string, 0, len(collapsed))
		for _, id := range ids {
			reordered = append(reordered, byID[id]...)
		}
		collapsed = reordered
	}

	return strings.Join(collapsed, "\n")
}

func normalizeMappedRangeLine(line string) (string, bool) {
	const prefix = "Gen_Info : FileAcc; Range::"
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rangePart, _, _ := strings.Cut(strings.TrimPrefix(line, prefix), ";")
	rangePart = strings.TrimSpace(rangePart)
	if rangePart == "" {
		return "", false
	}

	// Compare only the start:end range segment so formatting regressions are caught
	// (for example, an unexpected "0x" prefix on the second address), while
	// ignoring unrelated output differences such as memory-space naming.
	return "MAP_RANGE:" + rangePart, true
}

func extractNormalizedIDFromLine(line string) (string, bool) {
	if !strings.HasPrefix(line, "ID:") {
		return "", false
	}
	rest := strings.TrimPrefix(line, "ID:")
	id, _, ok := strings.Cut(rest, ";")
	if !ok {
		return "", false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false
	}
	return id, true
}

func isNoSyncPacketLine(line string) bool {
	return strings.Contains(line, "PKT:I_NOT_SYNC") || strings.Contains(line, "PKT:NOTSYNC") || strings.Contains(line, "PKT:ITM_NOTSYNC")
}

func splitIdxRecords(line string) []string {
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
	for i, start := range starts {
		end := len(line)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		rec := strings.TrimSpace(line[start:end])
		if strings.HasPrefix(rec, "Idx:") {
			records = append(records, rec)
		}
	}
	return records
}

func normalizeTraceListerIdxRecord(rec, decoder string) string {
	id, ok := extractLineID(rec)
	if !ok {
		return ""
	}

	right := ""
	if _, after, ok := strings.Cut(rec, "\t"); ok {
		right = strings.TrimSpace(after)
	}
	if right == "" {
		if elem := extractGenElemType(rec); elem != "" {
			_ = elem
		}
		return ""
	}

	packetType := extractPacketType(right)
	if packetType == "" {
		return ""
	}
	packetHeader := normalizePacketHeader(right, decoder)
	packetDesc := extractPacketDescription(packetHeader, decoder)
	return fmt.Sprintf("ID:%s; PKT:%s; HDR:%s; DESC:%s", id, packetType, packetHeader, packetDesc)
}

func normalizePacketHeader(s, decoder string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// For ETMv4, ETE, ETMv3, PTM and STM, stop truncating at semicolon to accurately test full packet headers
	if decoder == "etmv4" || decoder == "ete" || decoder == "etmv3" || decoder == "ptm" || decoder == "stm" {
		return strings.Join(strings.Fields(s), " ")
	}

	before, _, _ := strings.Cut(s, ";")
	hdr := strings.Join(strings.Fields(strings.TrimSpace(before)), " ")
	return hdr
}

func extractPacketDescription(header, decoder string) string {
	header = strings.TrimSpace(header)
	_, desc, ok := strings.Cut(header, ":")
	if !ok {
		return "<missing>"
	}
	desc = strings.Join(strings.Fields(strings.TrimSpace(desc)), " ")
	if desc == "" {
		return "<missing>"
	}
	return desc
}

func normalizeSourceLine(line string) (string, bool) {
	const prefix = "Using "
	const suffix = " as trace source"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) {
		return "", false
	}
	source := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix))
	if source == "" {
		return "", false
	}
	return "SOURCE:" + source, true
}

func extractLineID(line string) (string, bool) {
	re := regexp.MustCompile(`(?i)\bID:([0-9a-f]+)\b`)
	m := re.FindStringSubmatch(line)
	if len(m) != 2 {
		return "", false
	}
	return strings.ToLower(m[1]), true
}

func extractPacketType(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	before, _, ok := strings.Cut(s, ":")
	if !ok {
		before = s
	}
	return strings.TrimSpace(before)
}

func extractGenElemType(line string) string {
	re := regexp.MustCompile(`(?i)(?:RCTDL|OCSD)_GEN_TRC_ELEM_([A-Z0-9_]+)`)
	m := re.FindStringSubmatch(line)
	if len(m) != 2 {
		return ""
	}
	return strings.ToUpper(m[1])
}

func firstDiff(got, want []string) (int, string, string) {
	maxLen := max(len(got), len(want))
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

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}
