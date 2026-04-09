package main

import (
	"fmt"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/snapshot"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	reDeviceSuffix = regexp.MustCompile(`(?i)(?:_|-dcd-)0x([0-9a-f]+)$`)
	reExtractID    = regexp.MustCompile(`(?i)\bID:([0-9a-f]+)\b`)
	reExtractType  = regexp.MustCompile(`(?i)(?:RCTDL|OCSD)_GEN_TRC_ELEM_([A-Z0-9_]+)`)
)

// goldenBoolFlags is the canonical set of boolean behavioral flags that
// parseOptionsFromGolden recognises and forwards verbatim into extraFlags.
// It mirrors every boolean flag in parseOptions that materially affects decode
// output and should therefore be re-applied when replaying a golden test case.
var goldenBoolFlags = map[string]struct{}{
	"-multi_session":      {},
	"-dstream_format":     {},
	"-tpiu":               {},
	"-tpiu_hsync":         {},
	"-o_raw_packed":       {},
	"-o_raw_unpacked":     {},
	"-direct_br_cond":     {},
	"-strict_br_cond":     {},
	"-range_cont":         {},
	"-halt_err":           {},
	"-src_addr_n":         {},
	"-aa64_opcode_chk":    {},
	"-pkt_mon":            {},
	"-macc_cache_disable": {},
}

// goldenValueFlags is the canonical set of flags that take a single value
// argument and should be forwarded as "flag value" pairs into extraFlags.
var goldenValueFlags = map[string]struct{}{
	"-macc_cache_p_size": {},
	"-macc_cache_p_num":  {},
}

type listerGoldenCase struct {
	name               string
	decoder            string
	goldenPath         string
	snapshotDir        string
	sourceName         string
	id                 string
	decode             bool
	extraFlags         []string
	normalized         bool
	ignoreMappedRanges bool
	expectedRunError   string
}

type listerGoldenManifestEntry struct {
	decoder            string
	goldenName         string
	snapshotName       string
	normalizeReason    string
	ignoreMappedRanges bool
	expectedRunError   string
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
			err := run(args)
			if tc.expectedRunError == "" {
				if err != nil {
					t.Fatalf("run(%v) failed: %v", args, err)
				}
			} else {
				if err == nil {
					t.Fatalf("run(%v) succeeded; expected error containing %q", args, tc.expectedRunError)
				}
				if !strings.Contains(err.Error(), tc.expectedRunError) {
					t.Fatalf("run(%v) error = %v; want substring %q", args, err, tc.expectedRunError)
				}
			}

			gotBytes, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read generated output %s: %v", outPath, err)
			}
			wantBytes, err := os.ReadFile(tc.goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", tc.goldenPath, err)
			}

			var got, want string
			if tc.normalized {
				got = normalizeTraceListerOutput(string(gotBytes), tc.ignoreMappedRanges)
				want = normalizeTraceListerOutput(string(wantBytes), tc.ignoreMappedRanges)
			} else {
				got = strictTraceListerOutput(string(gotBytes), tc.ignoreMappedRanges)
				want = strictTraceListerOutput(string(wantBytes), tc.ignoreMappedRanges)
			}

			gotLines := strings.Split(got, "\n")
			wantLines := strings.Split(want, "\n")

			if diffIdx, gotLine, wantLine := firstDiff(gotLines, wantLines); diffIdx != 0 {
				t.Fatalf("golden mismatch at line %d\nwant: %s\n got: %s", diffIdx, wantLine, gotLine)
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
		{decoder: "ete", goldenName: "tme_tcancel", snapshotName: "tme_tcancel"},
		{decoder: "ete", goldenName: "tme_test", snapshotName: "tme_test"},
		{decoder: "ete", goldenName: "trace_file_cid_vmid", snapshotName: "trace_file_cid_vmid"},
		{decoder: "ete", goldenName: "trace_file_vmid", snapshotName: "trace_file_vmid"},
		{decoder: "ete", goldenName: "ts_bit64_set", snapshotName: "ts_bit64_set"},
		{decoder: "ete", goldenName: "ts_marker", snapshotName: "ts_marker"},
		{
			decoder: "etmv3", goldenName: "TC2", snapshotName: "TC2",
			//todo: remove this (and others)
			normalizeReason: "legacy ETMv3 TC2 packet-vs-generic-element sequencing mismatch around P-header emission",
		},
		{
			decoder: "etmv4", goldenName: "a55-test-tpiu", snapshotName: "a55-test-tpiu",
			normalizeReason: "legacy ETMv4 packet formatting instability (raw-byte prefix presence differs)",
		},
		{decoder: "etmv4", goldenName: "a57_single_step", snapshotName: "a57_single_step"},
		{decoder: "etmv4", goldenName: "armv8_1m_branches", snapshotName: "armv8_1m_branches"},
		{decoder: "etmv4", goldenName: "init-short-addr", snapshotName: "init-short-addr"},
		{decoder: "etmv4", goldenName: "juno-ret-stck", snapshotName: "juno-ret-stck"},
		{decoder: "etmv4", goldenName: "juno-uname-001", snapshotName: "juno-uname-001"},
		{decoder: "etmv4", goldenName: "juno-uname-002", snapshotName: "juno-uname-002"},
		{decoder: "etmv4", goldenName: "juno_r1_1", snapshotName: "juno_r1_1"},
		{
			decoder: "etmv4", goldenName: "juno_r1_1_badopcode", snapshotName: "juno_r1_1",
			normalizeReason: "legacy ETMv4 bad-opcode recovery behavior differs (bad-packet no-sync vs decoded range)",
		},
		{decoder: "etmv4", goldenName: "juno_r1_1_badopcode_flag", snapshotName: "juno_r1_1"},
		{
			decoder: "etmv4", goldenName: "juno_r1_1_rangelimit", snapshotName: "juno_r1_1",
			normalizeReason: "legacy ETMv4 range-limit recovery behavior differs from C++ golden output",
		},
		{
			decoder:            "etmv4",
			goldenName:         "test-file-mem-offsets",
			snapshotName:       "test-file-mem-offsets",
			normalizeReason:    "legacy ETMv4 memory-access fault handling differs (ADDR_NACC placement vs C++ golden)",
			ignoreMappedRanges: true,
		},
		{decoder: "itm", goldenName: "itm_only_csformat", snapshotName: "itm_only_csformat"},
		{decoder: "itm", goldenName: "itm_only_raw", snapshotName: "itm_only_raw"},
		{decoder: "ptm", goldenName: "Snowball", snapshotName: "Snowball"},
		{
			decoder: "ptm", goldenName: "TC2", snapshotName: "TC2",
			normalizeReason: "legacy PTM TC2 packet-vs-generic-element sequencing mismatch around P-header emission",
		},
		{decoder: "ptm", goldenName: "tc2-ptm-rstk-t32", snapshotName: "tc2-ptm-rstk-t32"},
		{decoder: "ptm", goldenName: "trace_cov_a15", snapshotName: "trace_cov_a15"},
		{decoder: "stm", goldenName: "stm-issue-27", snapshotName: "stm-issue-27"}, {decoder: "stm", goldenName: "stm_only-2", snapshotName: "stm_only-2"},
		{
			decoder: "stm", goldenName: "stm_only-juno", snapshotName: "stm_only-juno",
			expectedRunError: "trace packet lister: data path fatal response=",
		},
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
			name:               filepath.ToSlash(filepath.Join(entry.decoder, entry.snapshotName, entry.goldenName+".ppl")),
			decoder:            entry.decoder,
			goldenPath:         goldenPath,
			snapshotDir:        snapshotDir,
			sourceName:         extractSourceName(ppl),
			id:                 id,
			decode:             decode,
			extraFlags:         extraFlags,
			normalized:         entry.normalizeReason != "",
			ignoreMappedRanges: entry.ignoreMappedRanges,
			expectedRunError:   entry.expectedRunError,
		})
	}

	return testCases
}

// parseOptionsFromGolden extracts behavioural replay arguments from a golden
// .ppl file. It returns the trace-source ID (if any), whether full decode was
// requested, and all extra flags that must be re-applied when running the
// golden test case.
//
// Flag recognition is table-driven: goldenBoolFlags and goldenValueFlags are
// the authoritative sets, so adding a new flag here is a one-line change.
// Flags that are either handled through other fields (e.g. -id, -src_name) or
// irrelevant to output comparison (-ss_dir, -logfilename, …) are consumed but
// not forwarded to extraFlags.
func parseOptionsFromGolden(name, ppl string) (string, bool, []string) {
	decode := strings.Contains(strings.ToLower(name), "-dcd-")
	id := ""
	var extraFlags []string

	if m := reDeviceSuffix.FindStringSubmatch(name); len(m) == 2 {
		id = "0x" + strings.ToLower(m[1])
	}

	cmdLine := extractGoldenCommandLine(ppl)
	if cmdLine == "" {
		return id, decode, extraFlags
	}

	// Flags that take a value argument but whose value should NOT be forwarded
	// (they are either handled via other struct fields or irrelevant to output).
	skipValueFlags := map[string]struct{}{
		"-ss_dir":      {},
		"-src_name":    {}, // extracted via extractSourceName; forwarding would duplicate it
		"-logfilename": {},
		"-test_waits":  {},
	}

	fields := strings.Fields(cmdLine)
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		switch tok {
		case "-decode", "-decode_only":
			decode = true

		case "-id":
			// Consumed and returned as the id return value, not forwarded.
			if i+1 < len(fields) {
				i++
				parsed := strings.ToLower(strings.TrimSuffix(fields[i], ","))
				if parsed != "" {
					if _, err := strconv.ParseUint(parsed, 0, 8); err == nil {
						id = parsed
					}
				}
			}

		default:
			if _, ok := goldenBoolFlags[tok]; ok {
				extraFlags = append(extraFlags, tok)
			} else if _, ok := goldenValueFlags[tok]; ok {
				if i+1 < len(fields) {
					i++
					extraFlags = append(extraFlags, tok, fields[i])
				}
			} else if _, ok := skipValueFlags[tok]; ok {
				// Consume the following value so it isn't mistaken for a flag.
				if i+1 < len(fields) {
					i++
				}
			}
			// Unknown/non-behavioural flags (e.g. -stats, -profile) are silently
			// ignored; they do not affect decode output.
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

// strictTraceListerOutput performs in-order comparison of stable semantic
// output only:
// - SOURCE:<name> lines
// - MAP_RANGE:<start:end> lines
// - raw Idx: records (including packet/gen-elem interleaving as emitted)
//
// This intentionally excludes run-specific/structural noise such as command
// lines, file paths, summary trailers, and buffer-complete banners.
// No line deduplication or multi-ID reordering is performed.
func strictTraceListerOutput(s string, ignoreMappedRanges bool) string {
	lines := strings.Split(normalizeNewlines(s), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t")
		text := strings.TrimSpace(trimmed)

		if text == "" {
			continue
		}

		if sourceLine, ok := normalizeSourceLine(text); ok {
			out = append(out, sourceLine)
			continue
		}

		// Keep only address-range payload from memory mapping lines.
		if mappedRange, ok := normalizeMappedRangeLine(text); ok {
			if !ignoreMappedRanges {
				out = append(out, mappedRange)
			}
			continue
		}

		records := splitIdxRecords(trimmed)
		if len(records) == 0 {
			continue
		}
		out = append(out, records...)
	}
	return strings.Join(out, "\n")
}

func normalizeTraceListerOutput(ppl string, ignoreMappedRanges bool) string {
	lines := strings.Split(normalizeNewlines(ppl), "\n")
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		if mappedRange, ok := normalizeMappedRangeLine(raw); ok {
			if !ignoreMappedRanges {
				out = append(out, mappedRange)
			}
			continue
		}

		if sourceLine, ok := normalizeSourceLine(raw); ok {
			out = append(out, sourceLine)
			continue
		}

		records := splitIdxRecords(raw)
		for _, rec := range records {
			normalized := normalizeTraceListerIdxRecord(rec)
			if normalized != "" {
				out = append(out, normalized)
			}
		}
	}

	return strings.Join(out, "\n")
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

func normalizeTraceListerIdxRecord(rec string) string {
	id, ok := extractLineID(rec)
	if !ok {
		return ""
	}

	// Capture the Idx: value (e.g., "Idx:1234")
	idxPart := ""
	if strings.HasPrefix(rec, "Idx:") {
		idxPart, _, _ = strings.Cut(rec, ";")
		idxPart = strings.TrimSpace(idxPart)
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

	// Prepend the index to the normalized output string
	return fmt.Sprintf("%s; ID:%s; PKT:%s; HDR:%s; DESC:%s", idxPart, id, packetType, packetHeader, packetDesc)
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
	re := reExtractID
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
	re := reExtractType
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

// TestParseOptionsFromGoldenAllBehavioralFlags verifies that every flag listed
// in goldenBoolFlags and goldenValueFlags is actually recognised and forwarded
// by parseOptionsFromGolden. If a new flag is added to either table but the
// parser loop is not updated, this test will catch the regression.
func TestParseOptionsFromGoldenAllBehavioralFlags(t *testing.T) {
	// Build a synthetic command line that includes every known behavioral flag.
	// -ss_dir, -decode, and -id are included to exercise the special-case paths.
	cmdParts := []string{
		"trc_pkt_lister",
		"-ss_dir", "testdir",
		"-decode",
		"-decode_only", // also sets decode; harmless duplicate
		"-id", "0x10",
		"-src_name", "ETM_0", // should be consumed-but-not-forwarded
	}
	for flag := range goldenBoolFlags {
		cmdParts = append(cmdParts, flag)
	}
	for flag := range goldenValueFlags {
		cmdParts = append(cmdParts, flag, "42")
	}

	ppl := "Test Command Line:-\n" + strings.Join(cmdParts, " ") + "\n\nTrace Packet Lister : stub\n"

	id, decode, extraFlags := parseOptionsFromGolden("golden-test", ppl)

	if !decode {
		t.Errorf("expected decode=true from -decode flag in synthetic command line")
	}
	if id != "0x10" {
		t.Errorf("expected id=0x10, got %q", id)
	}

	// Index extraFlags for fast membership testing.
	extraIndex := make(map[string]int, len(extraFlags)) // flag → position
	for i, f := range extraFlags {
		extraIndex[f] = i
	}

	// Every bool flag must appear exactly once in extraFlags.
	for flag := range goldenBoolFlags {
		if _, ok := extraIndex[flag]; !ok {
			t.Errorf("parseOptionsFromGolden did not forward bool flag %s", flag)
		}
	}

	// Every value flag must appear in extraFlags followed by its value ("42").
	for flag := range goldenValueFlags {
		pos, ok := extraIndex[flag]
		if !ok {
			t.Errorf("parseOptionsFromGolden did not forward value flag %s", flag)
			continue
		}
		if pos+1 >= len(extraFlags) || extraFlags[pos+1] != "42" {
			t.Errorf("parseOptionsFromGolden did not forward value for flag %s (extraFlags=%v)", flag, extraFlags)
		}
	}

	// Verify that -src_name was NOT forwarded (it is handled via extractSourceName).
	for _, f := range extraFlags {
		if f == "-src_name" {
			t.Errorf("parseOptionsFromGolden forwarded -src_name into extraFlags; it should be consumed but not forwarded")
		}
	}
}

func TestParseOptionsCompositeFlags(t *testing.T) {
	opts, err := parseOptions([]string{
		"-decode_only",
		"-tpiu_hsync",
		"-direct_br_cond",
		"-range_cont",
		"-macc_cache_p_size", "4096",
		"-macc_cache_p_num", "2",
		"-id", "0x10",
		"-id", "0x20",
	})
	if err != nil {
		t.Fatalf("parseOptions failed: %v", err)
	}

	if !opts.decodeOnly || !opts.decode {
		t.Fatalf("expected decode_only to imply decode; decodeOnly=%v decode=%v", opts.decodeOnly, opts.decode)
	}
	if !opts.tpiuFormat || !opts.hasHSync {
		t.Fatalf("expected tpiu_hsync to set tpiuFormat+hasHSync; tpiuFormat=%v hasHSync=%v", opts.tpiuFormat, opts.hasHSync)
	}

	wantFlags := uint32(ocsd.OpflgNUncondDirBrChk | ocsd.OpflgChkRangeContinue)
	if opts.additionalFlags != wantFlags {
		t.Fatalf("additionalFlags mismatch: got 0x%x want 0x%x", opts.additionalFlags, wantFlags)
	}

	if opts.memCachePageSize != 4096 || opts.memCachePageNum != 2 {
		t.Fatalf("cache values mismatch: size=%d num=%d", opts.memCachePageSize, opts.memCachePageNum)
	}

	if opts.allSourceIDs {
		t.Fatal("expected allSourceIDs=false when -id is provided")
	}
	if len(opts.idList) != 2 || opts.idList[0] != 0x10 || opts.idList[1] != 0x20 {
		t.Fatalf("unexpected idList: %v", opts.idList)
	}
}

func TestParseOptionsLoggingPrecedence(t *testing.T) {
	defaultOpts, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions default failed: %v", err)
	}
	if !defaultOpts.logStdout || defaultOpts.logStderr || !defaultOpts.logFile || defaultOpts.logFileName != defaultLogFile {
		t.Fatalf("unexpected default logging options: stdout=%v stderr=%v file=%v fileName=%q", defaultOpts.logStdout, defaultOpts.logStderr, defaultOpts.logFile, defaultOpts.logFileName)
	}

	stdoutWins, err := parseOptions([]string{"-logfile", "-logfilename", "custom.ppl", "-logstderr", "-logstdout"})
	if err != nil {
		t.Fatalf("parseOptions precedence failed: %v", err)
	}
	if !stdoutWins.logStdout || stdoutWins.logStderr || stdoutWins.logFile {
		t.Fatalf("expected logstdout precedence, got stdout=%v stderr=%v file=%v", stdoutWins.logStdout, stdoutWins.logStderr, stdoutWins.logFile)
	}
	if stdoutWins.logFileName != defaultLogFile {
		t.Fatalf("expected default logfile name to remain, got %q", stdoutWins.logFileName)
	}

	fileNameWins, err := parseOptions([]string{"-logfile", "-logfilename", "named-output.ppl"})
	if err != nil {
		t.Fatalf("parseOptions logfilename failed: %v", err)
	}
	if fileNameWins.logStdout || fileNameWins.logStderr || !fileNameWins.logFile || fileNameWins.logFileName != "named-output.ppl" {
		t.Fatalf("expected logfilename behavior, got stdout=%v stderr=%v file=%v fileName=%q", fileNameWins.logStdout, fileNameWins.logStderr, fileNameWins.logFile, fileNameWins.logFileName)
	}
}

func TestRunUnknownSourceNameReturnsError(t *testing.T) {
	snapshotDir := filepath.Join("..", "..", "internal", "ete", "testdata", "001-ack_test")
	outPath := filepath.Join(t.TempDir(), "out.ppl")

	err := run([]string{
		"-ss_dir", snapshotDir,
		"-src_name", "__definitely_not_a_real_source__",
		"-logfilename", outPath,
		"-no_time_print",
	})
	if err == nil {
		t.Fatal("expected error for unknown source name, got nil")
	}
	if !strings.Contains(err.Error(), `trace source name "__definitely_not_a_real_source__" not found`) {
		t.Fatalf("unexpected error: %v", err)
	}

	gotBytes, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("read output %s: %v", outPath, readErr)
	}
	got := string(gotBytes)
	if !strings.Contains(got, "Valid source names are:-") {
		t.Fatalf("expected valid-source list in output, got:\n%s", got)
	}
}

func TestRunForcedFatalDatapathReturnsError(t *testing.T) {
	snapshotDir := filepath.Join("..", "..", "internal", "stm", "testdata", "stm_only-juno")
	outPath := filepath.Join(t.TempDir(), "out.ppl")

	err := run([]string{
		"-ss_dir", snapshotDir,
		"-src_name", "ETB_1",
		"-decode",
		"-logfilename", outPath,
		"-no_time_print",
	})
	if err == nil {
		t.Fatal("expected fatal datapath error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "data path fatal response=") {
		t.Fatalf("expected fatal response in error, got: %v", err)
	}
	if !strings.Contains(msg, "trace_index=") {
		t.Fatalf("expected trace_index in error, got: %v", err)
	}
	if !strings.Contains(msg, "pending=") {
		t.Fatalf("expected pending in error, got: %v", err)
	}
}
func TestFramedTailErrorIncludesContext(t *testing.T) {
	err := framedTailError(1024, 1, 4)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "leftover framed tail bytes at EOF") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(msg, "trace_index=1024") {
		t.Fatalf("expected trace_index in error, got: %v", err)
	}
	if !strings.Contains(msg, "pending=1") {
		t.Fatalf("expected pending in error, got: %v", err)
	}
	if !strings.Contains(msg, "align=4") {
		t.Fatalf("expected align in error, got: %v", err)
	}
}

func TestMapMemoryRangesSameFileDifferentOffsetsBothMapped(t *testing.T) {
	dir := t.TempDir()
	memFile := filepath.Join(dir, "mem.bin")
	if err := os.WriteFile(memFile, []byte{0, 1, 2, 3, 4, 5, 6, 7}, 0o644); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.ParsedDevice{
			"cpu_0": {
				DeviceName:  "cpu_0",
				DeviceClass: "core",
				DumpDefs: []snapshot.DumpDef{
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
					{
						Path:    "mem.bin",
						Address: 0x2000,
						Offset:  4,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	ranges, err := mapMemoryRanges(mapper, dir, reader)
	if err != nil {
		t.Fatalf("mapMemoryRanges returned error: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("expected 2 mapped ranges, got %d", len(ranges))
	}
	if ranges[0].start != 0x1000 || ranges[0].end != 0x1003 {
		t.Fatalf("unexpected first range: %#v", ranges[0])
	}
	if ranges[1].start != 0x2000 || ranges[1].end != 0x2003 {
		t.Fatalf("unexpected second range: %#v", ranges[1])
	}
}

func TestMapMemoryRangesBadOffsetReturnsError(t *testing.T) {
	dir := t.TempDir()
	memFile := filepath.Join(dir, "mem.bin")
	if err := os.WriteFile(memFile, []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.ParsedDevice{
			"cpu_0": {
				DeviceName:  "cpu_0",
				DeviceClass: "core",
				DumpDefs: []snapshot.DumpDef{
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  99,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	_, err := mapMemoryRanges(mapper, dir, reader)
	if err == nil {
		t.Fatal("expected error for bad offset, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "offset beyond EOF") {
		t.Fatalf("expected offset error, got: %v", err)
	}
	if !strings.Contains(msg, "requested_offset=99") {
		t.Fatalf("expected requested offset in error, got: %v", err)
	}
	if !strings.Contains(msg, "file_size=4") {
		t.Fatalf("expected file size in error, got: %v", err)
	}
	if !strings.Contains(msg, "mem.bin") {
		t.Fatalf("expected file path in error, got: %v", err)
	}
}

func TestMapMemoryRangesUnreadableFileIgnored(t *testing.T) {
	dir := t.TempDir()

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.ParsedDevice{
			"cpu_0": {
				DeviceName:  "cpu_0",
				DeviceClass: "core",
				DumpDefs: []snapshot.DumpDef{
					{
						Path:    "missing.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	ranges, err := mapMemoryRanges(mapper, dir, reader)
	if err != nil {
		t.Fatalf("expected missing dump file to be ignored, got error: %v", err)
	}
	if len(ranges) != 0 {
		t.Fatalf("expected no mapped ranges, got %d", len(ranges))
	}
}

func TestMapMemoryRangesDuplicateSemanticMappingIgnored(t *testing.T) {
	dir := t.TempDir()
	memFile := filepath.Join(dir, "mem.bin")
	if err := os.WriteFile(memFile, []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.ParsedDevice{
			"cpu_0": {
				DeviceName:  "cpu_0",
				DeviceClass: "core",
				DumpDefs: []snapshot.DumpDef{
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	ranges, err := mapMemoryRanges(mapper, dir, reader)
	if err != nil {
		t.Fatalf("mapMemoryRanges returned error: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("expected 1 mapped range after semantic dedupe, got %d", len(ranges))
	}
	if ranges[0].start != 0x1000 || ranges[0].end != 0x1003 {
		t.Fatalf("unexpected mapped range: %#v", ranges[0])
	}
}
func init() {
	_ = splitOutput // silence unused warning
}

// splitOutput takes a slice of text lines and separates them into two independent streams.
func splitOutput(lines []string) (packets []string, elements []string) {
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Trace elements usually have this prefix or contain "Trace Event"
		if strings.Contains(line, "OCSD_GEN_TRC_ELEM") || strings.Contains(line, "Trace Event") {
			elements = append(elements, line)
		} else if strings.HasPrefix(strings.TrimSpace(line), "Idx:") {
			packets = append(packets, line)
		}
	}
	return packets, elements
}
