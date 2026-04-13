package ptm_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opencsd/internal/dcdtree"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	ptm "opencsd/internal/ptm"
	"opencsd/internal/snapshot"
	"opencsd/internal/testutil"
)

type mapperAdapter struct {
	mapper memacc.Mapper
}

type ptmRawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
}

func (p *ptmRawPacketPrinter) MonitorRawData(indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if p.writer == nil || pkt == nil || len(rawData) == 0 {
		return
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Idx:%d; ID:%x; [", indexSOP, p.traceID)
	for _, b := range rawData {
		fmt.Fprintf(&sb, "0x%02x ", b)
	}
	sb.WriteString("];\t")
	sb.WriteString(pkt.String())
	sb.WriteString("\n")
	_, _ = io.WriteString(p.writer, sb.String())
}

func (p *ptmRawPacketPrinter) MonitorEOT() {}

func (p *ptmRawPacketPrinter) MonitorReset(indexSOP ocsd.TrcIndex) {}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	buf := make([]byte, reqBytes)
	readBytes, err := m.mapper.Read(address, csTraceID, memSpace, reqBytes, buf)
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
				line, gotLine, wantLine := testutil.FirstDiff(gotLines, wantLines)
				t.Fatalf("snapshot mismatch at line %d\nwant: %s\n got: %s", line, wantLine, gotLine)
			}
		})
	}
}

func runSnapshotDecode(snapshotDir, sourceName string) ([]byte, error) {
	reader := snapshot.NewReader()
	reader.SetDir(snapshotDir)
	if err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
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
	switch dataFormat {
	case "source_data":
		srcIsFrame = false
	case "dstream_coresight":
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

	tree, err := dcdtree.NewDecodeTree(srcType, formatterFlags)
	if err != nil {
		return nil, fmt.Errorf("create decode tree: %w", err)
	}
	if tree == nil {
		return nil, fmt.Errorf("nil decode tree")
	}

	mapper := memacc.NewGlobalMapper()
	memIf := &mapperAdapter{mapper: mapper}
	instr := idec.NewDecoder()

	ptmDecoders := 0
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := testutil.FindParsedDeviceByName(reader.ParsedDeviceList, srcDevName)
		if dev == nil {
			continue
		}
		devType := strings.ToUpper(dev.DeviceTypeName)
		if !strings.HasPrefix(devType, "PTM") && !strings.HasPrefix(devType, "PFT") {
			continue
		}

		cfg := ptm.NewConfig()
		if val, ok := dev.RegValue("etmcr"); ok {
			cfg.RegCtrl = uint32(testutil.ParseHexOrDec(val))
		}
		if val, ok := dev.RegValue("etmtraceidr"); ok {
			cfg.RegTrcID = uint32(testutil.ParseHexOrDec(val))
		}
		if val, ok := dev.RegValue("etmidr"); ok {
			cfg.RegIDR = uint32(testutil.ParseHexOrDec(val))
		}
		if val, ok := dev.RegValue("etmccer"); ok {
			cfg.RegCCER = uint32(testutil.ParseHexOrDec(val))
		}

		traceID := cfg.TraceID()
		proc, dec, err := ptm.NewConfiguredPipelineWithDeps(int(traceID), cfg, memIf, instr)
		if err != nil {
			return nil, fmt.Errorf("create PTM pipeline for %s failed: %v", srcDevName, err)
		}

		if err := tree.AddPullDecoder(traceID, ocsd.BuiltinDcdPTM, ocsd.ProtocolPTM, proc, dec, dec); err != nil {
			return nil, fmt.Errorf("attach PTM decoder for %s failed: %v", srcDevName, err)
		}
		ptmDecoders++
	}

	if ptmDecoders == 0 {
		return nil, fmt.Errorf("no PTM decoders found for source %s", sourceName)
	}

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
	tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
		proc, ok := elem.DataIn.(*ptm.PktProc)
		if !ok || proc == nil {
			return
		}
		proc.SetPktRawMonitor(&ptmRawPacketPrinter{writer: &out, traceID: csID})
	})
	if err := drainAndPrintElements(tree, printer); err != nil {
		return nil, err
	}

	binFile := filepath.Join(snapshotDir, sourceTree.BufferInfo.DataFileName)
	traceData, err := os.ReadFile(binFile)
	if err != nil {
		return nil, fmt.Errorf("read trace buffer %s: %w", binFile, err)
	}

	var traceIndex uint32
	if srcIsFrame {
		pending := traceData
		for len(pending) >= frameAlignment {
			sendLen := frameAlignment
			consumed, err := tree.Write(ocsd.TrcIndex(traceIndex), pending[:sendLen])
			resp := ocsd.DataRespFromErr(err)
			if ocsd.DataRespIsFatal(resp) {
				return nil, fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
			}
			if consumed == 0 {
				return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			pending = pending[consumed:]
			if err := drainAndPrintElements(tree, printer); err != nil {
				return nil, err
			}
		}
	} else {
		remaining := traceData
		for len(remaining) > 0 {
			sendLen := min(len(remaining), 256)
			consumed, err := tree.Write(ocsd.TrcIndex(traceIndex), remaining[:sendLen])
			resp := ocsd.DataRespFromErr(err)
			if ocsd.DataRespIsFatal(resp) {
				return nil, fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
			}
			if consumed == 0 {
				return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			remaining = remaining[consumed:]
			if err := drainAndPrintElements(tree, printer); err != nil {
				return nil, err
			}
		}
	}

	err = tree.Close()
	resp := ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		return nil, fmt.Errorf("fatal datapath response on EOT")
	}
	if err := drainAndPrintElements(tree, printer); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func drainAndPrintElements(tree *dcdtree.DecodeTree, printer *printers.GenericElementPrinter) error {
	if tree == nil || printer == nil {
		return nil
	}
	for elem, err := range tree.Elements() {
		if err != nil {
			if errors.Is(err, ocsd.ErrWait) {
				break
			}
			return err
		}
		if printErr := printer.PrintElement(elem); printErr != nil && !ocsd.IsDataWaitErr(printErr) {
			return printErr
		}
	}
	return nil
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

		for _, idxLine := range testutil.SplitIdxRecords(line) {
			normalized := testutil.NormalizeSnapshotLine(idxLine)
			if normalized == "" {
				continue
			}
			if !strings.Contains(normalized, "OCSD_GEN_TRC_ELEM_") {
				continue
			}

			idVal, ok := testutil.ExtractLineID(idxLine)
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

	byID := make(map[string][]string, len(idSet))
	for _, entry := range parsed {
		if _, ok := idSet[entry.id]; ok {
			byID[entry.id] = append(byID[entry.id], entry.line)
		}
	}

	// Legacy PTM traces (e.g. trace_cov_a15) encode generic element lines with ID:2
	// while packets use ID:0. If filtering by trace ID 0 would remove all generic lines,
	// keep ID:2 generic lines as part of the PTM stream.
	if _, hasZero := idSet["0"]; hasZero {
		if len(byID["0"]) == 0 {
			fallback := make([]string, 0)
			for _, entry := range parsed {
				if entry.id == "2" {
					fallback = append(fallback, entry.line)
				}
			}
			if len(fallback) > 0 {
				byID["0"] = append(byID["0"], fallback...)
			}
		}
	}

	out := make([]string, 0, len(parsed))
	for _, rawID := range traceIDs {
		id := strings.ToLower(strings.TrimSpace(rawID))
		out = append(out, byID[id]...)
	}

	return strings.Join(out, "\n")
}
