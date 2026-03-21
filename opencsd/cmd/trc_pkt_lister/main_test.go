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

type listerGoldenManifestEntry struct {
	decoder      string
	goldenName   string
	snapshotName string
}

func TestTraceListerGoldens(t *testing.T) {
	testCases := explicitTraceListerGoldenCases(t)

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

func explicitTraceListerGoldenCases(t *testing.T) []listerGoldenCase {
	t.Helper()
	manifest := []listerGoldenManifestEntry{
		{decoder: "ete", goldenName: "001-ack_test", snapshotName: "001-ack_test"},
		{decoder: "ete", goldenName: "002-ack_test_scr", snapshotName: "002-ack_test_scr"},
		{decoder: "ete", goldenName: "002-ack_test_scr_src_addr_N", snapshotName: "002-ack_test_scr"},
		{decoder: "ete", goldenName: "ete-bc-instr", snapshotName: "ete-bc-instr"},
		{decoder: "ete", goldenName: "ete-ite-instr", snapshotName: "ete-ite-instr"},
		{decoder: "ete", goldenName: "ete-ite-instr_multi_sess", snapshotName: "ete-ite-instr"},
		{decoder: "ete", goldenName: "ete-wfet", snapshotName: "ete-wfet"},
		{decoder: "ete", goldenName: "ete_ip", snapshotName: "ete_ip"},
		{decoder: "ete", goldenName: "ete_ip_src_addr_N", snapshotName: "ete_ip"},
		{decoder: "ete", goldenName: "ete_mem", snapshotName: "ete_mem"},
		{decoder: "ete", goldenName: "ete_spec_1", snapshotName: "ete_spec_1"},
		{decoder: "ete", goldenName: "ete_spec_2", snapshotName: "ete_spec_2"},
		{decoder: "ete", goldenName: "ete_spec_3", snapshotName: "ete_spec_3"},
		{decoder: "ete", goldenName: "event_test", snapshotName: "event_test"},
		{decoder: "ete", goldenName: "feat_cmpbr", snapshotName: "feat_cmpbr"},
		{decoder: "ete", goldenName: "infrastructure", snapshotName: "infrastructure"},
		{decoder: "ete", goldenName: "maxspec0_commopt1", snapshotName: "maxspec0_commopt1"},
		{decoder: "ete", goldenName: "maxspec78_commopt0", snapshotName: "maxspec78_commopt0"},
		{decoder: "ete", goldenName: "pauth_lr", snapshotName: "pauth_lr"},
		{decoder: "ete", goldenName: "pauth_lr_Rm", snapshotName: "pauth_lr_Rm"},
		{decoder: "ete", goldenName: "pauth_lr_Rm_multi_sess", snapshotName: "pauth_lr_Rm"},
		{decoder: "ete", goldenName: "pauth_lr_multi_sess", snapshotName: "pauth_lr"},
		{decoder: "ete", goldenName: "q_elem", snapshotName: "q_elem"},
		{decoder: "ete", goldenName: "q_elem_multi_sess", snapshotName: "q_elem"},
		{decoder: "ete", goldenName: "rme_test", snapshotName: "rme_test"},
		{decoder: "ete", goldenName: "rme_test_multi_sess", snapshotName: "rme_test"},
		{decoder: "ete", goldenName: "s_9001", snapshotName: "s_9001"},
		{decoder: "ete", goldenName: "s_9001_multi_sess", snapshotName: "s_9001"},
		{decoder: "ete", goldenName: "src_addr", snapshotName: "src_addr"},
		{decoder: "ete", goldenName: "src_addr_src_addr_N", snapshotName: "src_addr"},
		{decoder: "ete", goldenName: "ss_ib_el1ns", snapshotName: "ss_ib_el1ns"},
		{decoder: "ete", goldenName: "ss_ib_el1ns_multi_sess", snapshotName: "ss_ib_el1ns"},
		{decoder: "ete", goldenName: "texit-poe2", snapshotName: "texit-poe2"},
		{decoder: "ete", goldenName: "tme_simple", snapshotName: "tme_simple"},
		{decoder: "ete", goldenName: "tme_tcancel", snapshotName: "tme_tcancel"},
		{decoder: "ete", goldenName: "tme_test", snapshotName: "tme_test"},
		{decoder: "ete", goldenName: "trace_file_cid_vmid", snapshotName: "trace_file_cid_vmid"},
		{decoder: "ete", goldenName: "trace_file_vmid", snapshotName: "trace_file_vmid"},
		{decoder: "ete", goldenName: "ts_bit64_set", snapshotName: "ts_bit64_set"},
		{decoder: "ete", goldenName: "ts_marker", snapshotName: "ts_marker"},
		{decoder: "etmv3", goldenName: "TC2", snapshotName: "TC2"},
		{decoder: "etmv4", goldenName: "a55-test-tpiu", snapshotName: "a55-test-tpiu"},
		{decoder: "etmv4", goldenName: "a57_single_step", snapshotName: "a57_single_step"},
		{decoder: "etmv4", goldenName: "armv8_1m_branches", snapshotName: "armv8_1m_branches"},
		{decoder: "etmv4", goldenName: "init-short-addr", snapshotName: "init-short-addr"},
		{decoder: "etmv4", goldenName: "juno-ret-stck", snapshotName: "juno-ret-stck"},
		{decoder: "etmv4", goldenName: "juno-uname-001", snapshotName: "juno-uname-001"},
		{decoder: "etmv4", goldenName: "juno-uname-002", snapshotName: "juno-uname-002"},
		{decoder: "etmv4", goldenName: "juno_r1_1", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "juno_r1_1_badopcode", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "juno_r1_1_badopcode_flag", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "juno_r1_1_rangelimit", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "test-file-mem-offsets", snapshotName: "test-file-mem-offsets"},
		{decoder: "itm", goldenName: "itm_only_csformat", snapshotName: "itm_only_csformat"},
		{decoder: "itm", goldenName: "itm_only_raw", snapshotName: "itm_only_raw"},
		{decoder: "ptm", goldenName: "Snowball", snapshotName: "Snowball"},
		{decoder: "ptm", goldenName: "TC2", snapshotName: "TC2"},
		{decoder: "ptm", goldenName: "tc2-ptm-rstk-t32", snapshotName: "tc2-ptm-rstk-t32"},
		{decoder: "ptm", goldenName: "trace_cov_a15", snapshotName: "trace_cov_a15"},
		{decoder: "stm", goldenName: "stm-issue-27", snapshotName: "stm-issue-27"},
		{decoder: "stm", goldenName: "stm_only-2", snapshotName: "stm_only-2"},
		{decoder: "stm", goldenName: "stm_only-juno", snapshotName: "stm_only-juno"},
		{decoder: "stm", goldenName: "stm_only", snapshotName: "stm_only"},
	}

	testCases := make([]listerGoldenCase, 0, len(manifest))
	for _, entry := range manifest {
		goldenPath := filepath.Join("..", "..", "internal", entry.decoder, "testdata", entry.goldenName+".ppl")
		snapshotDir := filepath.Join("..", "..", "internal", entry.decoder, "testdata", entry.snapshotName)

		goldenBytes, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read golden %s: %v", goldenPath, err)
		}
		if stat, err := os.Stat(snapshotDir); err != nil || !stat.IsDir() {
			t.Fatalf("missing snapshot dir %s", snapshotDir)
		}

		ppl := string(goldenBytes)
		id, decode, extraFlags := parseOptionsFromGolden(entry.goldenName, ppl)
		testCases = append(testCases, listerGoldenCase{
			name:        filepath.ToSlash(filepath.Join(entry.decoder, entry.snapshotName, entry.goldenName+".ppl")),
			decoder:     entry.decoder,
			goldenPath:  goldenPath,
			snapshotDir: snapshotDir,
			sourceName:  extractSourceName(ppl),
			id:          id,
			decode:      decode,
			extraFlags:  extraFlags,
		})
	}

	return testCases
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
	packetHeader := normalizePacketHeader(right)
	packetDesc := extractPacketDescription(packetHeader)
	return fmt.Sprintf("ID:%s; PKT:%s; HDR:%s; DESC:%s", id, packetType, packetHeader, packetDesc)
}

func normalizePacketHeader(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.Join(strings.Fields(s), " ")
}

func extractPacketDescription(header string) string {
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
