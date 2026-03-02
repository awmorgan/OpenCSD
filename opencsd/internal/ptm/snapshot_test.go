package ptm_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"opencsd/internal/dcdtree"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	ptm "opencsd/internal/ptm"
	"opencsd/internal/snapshot"
)

type mapperAdapter struct {
	mapper memacc.Mapper
}

type ptmRawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
}

func (p *ptmRawPacketPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *ptm.Packet, rawData []byte) {
	if p.writer == nil || op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Idx:%d; ID:%x; [", indexSOP, p.traceID))
	for _, b := range rawData {
		sb.WriteString(fmt.Sprintf("0x%02x ", b))
	}
	sb.WriteString("];\t")
	sb.WriteString(pkt.String())
	sb.WriteString("\n")
	_, _ = io.WriteString(p.writer, sb.String())
}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	buf := make([]byte, reqBytes)
	readBytes := reqBytes
	err := m.mapper.ReadTargetMemory(address, csTraceID, memSpace, &readBytes, buf)
	return readBytes, buf[:readBytes], err
}

func (m *mapperAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

func TestPTMSnapshotsAgainstGolden(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		sourceName string
		traceIDs   []string
	}{
		{name: "tc2-ptm-rstk-t32", sourceName: "PTM_0_2", traceIDs: []string{"0"}},
		{name: "TC2", sourceName: "ETB_0", traceIDs: []string{"13", "14"}},
		{name: "Snowball", sourceName: "ETB_0", traceIDs: []string{"10", "11"}},
		{name: "trace_cov_a15", sourceName: "PTM_0_2", traceIDs: []string{"0"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			snapshotDir := filepath.Join("testdata", tc.name)
			goldenPath := filepath.Join("testdata", tc.name+".ppl")

			goOut, err := runSnapshotDecode(snapshotDir, tc.sourceName)
			if err != nil {
				t.Fatalf("runSnapshotDecode failed: %v", err)
			}

			goldenBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden file %s: %v", goldenPath, err)
			}

			got := sanitizePPL(string(goOut), tc.traceIDs)
			want := sanitizePPL(string(goldenBytes), tc.traceIDs)

			if got != want {
				gotLines := strings.Split(got, "\n")
				wantLines := strings.Split(want, "\n")
				line, gotLine, wantLine := firstDiff(gotLines, wantLines)
				t.Fatalf("snapshot mismatch at line %d\nwant: %s\n got: %s", line, wantLine, gotLine)
			}
		})
	}
}

func runSnapshotDecode(snapshotDir, sourceName string) ([]byte, error) {
	reader := snapshot.NewReader()
	reader.SetSnapshotDir(snapshotDir)
	if !reader.ReadSnapShot() {
		return nil, fmt.Errorf("failed to read snapshot: %s", snapshotDir)
	}

	if reader.ParsedTrace == nil {
		return nil, fmt.Errorf("missing parsed trace metadata")
	}

	sourceTree := snapshot.NewTraceBufferSourceTree()
	if !snapshot.ExtractSourceTree(sourceName, reader.ParsedTrace, sourceTree) || sourceTree.BufferInfo == nil {
		return nil, fmt.Errorf("failed to extract source tree for %s", sourceName)
	}

	dataFormat := strings.ToLower(sourceTree.BufferInfo.DataFormat)
	srcIsFrame := true
	frameAlignment := 16
	if dataFormat == "source_data" {
		srcIsFrame = false
	} else if dataFormat == "dstream_coresight" {
		frameAlignment = 4
	}

	formatterFlags := uint32(ocsd.DfrmtrFrameMemAlign)
	if dataFormat == "dstream_coresight" {
		formatterFlags = ocsd.DfrmtrHasFsyncs
	}

	srcType := ocsd.TrcSrcFrameFormatted
	if !srcIsFrame {
		srcType = ocsd.TrcSrcSingle
	}

	tree := dcdtree.CreateDecodeTree(srcType, formatterFlags)
	if tree == nil {
		return nil, fmt.Errorf("nil decode tree")
	}

	ptmDecoders := 0
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := findParsedDeviceByName(reader.ParsedDeviceList, srcDevName)
		if dev == nil {
			continue
		}
		devType := strings.ToUpper(dev.DeviceTypeName)
		if !strings.HasPrefix(devType, "PTM") && !strings.HasPrefix(devType, "PFT") {
			continue
		}

		cfg := ptm.NewConfig()
		if val, ok := dev.GetRegValue("etmcr"); ok {
			cfg.RegCtrl = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("etmtraceidr"); ok {
			cfg.RegTrcID = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("etmidr"); ok {
			cfg.RegIDR = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("etmccer"); ok {
			cfg.RegCCER = uint32(parseHexOrDec(val))
		}

		if err := tree.CreateDecoder(ocsd.BuiltinDcdPTM, int(ocsd.CreateFlgFullDecoder), cfg); err != ocsd.OK {
			return nil, fmt.Errorf("create PTM decoder for %s failed: %v", srcDevName, err)
		}
		ptmDecoders++
	}

	if ptmDecoders == 0 {
		return nil, fmt.Errorf("no PTM decoders found for source %s", sourceName)
	}

	mapper := memacc.NewGlobalMapper()
	tree.SetMemAccessI(&mapperAdapter{mapper: mapper})

	for _, dev := range reader.ParsedDeviceList {
		if !strings.EqualFold(dev.DeviceClass, "core") {
			continue
		}
		for _, memParams := range dev.DumpDefs {
			path := filepath.Join(snapshotDir, memParams.Path)
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			if memParams.Offset > 0 {
				if memParams.Offset >= uint64(len(b)) {
					continue
				}
				b = b[memParams.Offset:]
			}
			if memParams.Length > 0 && memParams.Length < uint64(len(b)) {
				b = b[:memParams.Length]
			}

			acc := memacc.NewBufferAccessor(ocsd.VAddr(memParams.Address), b)
			mapper.AddAccessor(acc, 0)
		}
	}

	var out bytes.Buffer
	printer := printers.NewGenericElementPrinter(&out)
	tree.SetGenTraceElemOutI(printer)
	tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
		proc, ok := elem.DataIn.(*ptm.PktProc)
		if !ok || proc == nil {
			return
		}
		_ = proc.PktRawMonI.ReplaceFirst(&ptmRawPacketPrinter{writer: &out, traceID: csID})
	})

	binFile := filepath.Join(snapshotDir, sourceTree.BufferInfo.DataFileName)
	traceData, err := os.ReadFile(binFile)
	if err != nil {
		return nil, fmt.Errorf("read trace buffer %s: %w", binFile, err)
	}

	var traceIndex uint32
	if srcIsFrame {
		pending := traceData
		for len(pending) >= frameAlignment {
			sendLen := len(pending) - (len(pending) % frameAlignment)
			consumed, resp := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			if ocsd.DataRespIsFatal(resp) {
				return nil, fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
			}
			if consumed == 0 {
				return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			pending = pending[consumed:]
		}
	} else {
		remaining := traceData
		for len(remaining) > 0 {
			consumed, resp := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), remaining)
			if ocsd.DataRespIsFatal(resp) {
				return nil, fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
			}
			if consumed == 0 {
				return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			remaining = remaining[consumed:]
		}
	}

	_, resp := tree.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(traceIndex), nil)
	if ocsd.DataRespIsFatal(resp) {
		return nil, fmt.Errorf("fatal datapath response on EOT")
	}

	return out.Bytes(), nil
}

func sanitizePPL(s string, traceIDs []string) string {
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
		line string
		id   string
	}

	parsed := make([]parsedLine, 0, len(lines)-start)
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		for _, idxLine := range splitIdxRecords(line) {
			normalized := normalizeSnapshotLine(idxLine)
			if normalized == "" {
				continue
			}

			idVal, ok := extractLineID(idxLine)
			if !ok {
				continue
			}
			parsed = append(parsed, parsedLine{line: normalized, id: idVal})
		}
	}

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

	// Legacy PTM traces (e.g. trace_cov_a15) encode generic element lines with ID:2
	// while packets use ID:0. If filtering by trace ID 0 would remove all generic lines,
	// keep ID:2 generic lines as part of the PTM stream.
	if _, hasZero := idSet["0"]; hasZero {
		hasGeneric := false
		hasKeptGeneric := false
		for _, entry := range parsed {
			if strings.Contains(entry.line, "OCSD_GEN_TRC_ELEM_") {
				hasGeneric = true
				if containsLine(out, entry.line) {
					hasKeptGeneric = true
				}
			}
		}
		if hasGeneric && !hasKeptGeneric {
			for _, entry := range parsed {
				if entry.id == "2" && strings.Contains(entry.line, "OCSD_GEN_TRC_ELEM_") {
					out = append(out, entry.line)
				}
			}
		}
	}

	return strings.Join(out, "\n")
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

func normalizeSnapshotLine(line string) string {
	if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
		return line
	}

	left, right, ok := strings.Cut(line, "\t")
	if !ok {
		return ""
	}
	packetType := extractPacketType(strings.TrimSpace(right))
	if packetType == "" {
		return ""
	}
	return strings.TrimSpace(left) + "\t" + packetType
}

func extractPacketType(s string) string {
	if s == "" {
		return ""
	}
	before, _, ok := strings.Cut(s, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(before)
}

func containsLine(lines []string, target string) bool {
	return slices.Contains(lines, target)
}

func firstDiff(got, want []string) (int, string, string) {
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

func findParsedDeviceByName(devs map[string]*snapshot.ParsedDevice, name string) *snapshot.ParsedDevice {
	for _, dev := range devs {
		if dev != nil && dev.DeviceName == name {
			return dev
		}
	}
	return nil
}

func parseHexOrDec(s string) uint64 {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, _ := strconv.ParseUint(s[2:], 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func extractLineID(line string) (string, bool) {
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
