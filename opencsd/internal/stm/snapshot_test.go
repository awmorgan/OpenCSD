package stm_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opencsd/internal/dcdtree"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
	"opencsd/internal/stm"
	"opencsd/internal/testutil"
)

type stmRawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
}

func (p *stmRawPacketPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *stm.Packet, rawData []byte) {
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

func TestSTMSnapshotsAgainstGolden(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		sourceName string
		traceIDs   []string
	}{
		{name: "stm_only", sourceName: "ETB_1", traceIDs: []string{"20"}},
		{name: "stm_only-2", sourceName: "ETB_1", traceIDs: []string{"20"}},
		{name: "stm_only-juno", sourceName: "ETB_1", traceIDs: []string{"20"}},
		{name: "stm-issue-27", sourceName: "ETB_0", traceIDs: []string{"10"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			snapshotDir := filepath.Join("testdata", tc.name)
			goldenPath := filepath.Join("testdata", tc.name+".ppl")

			goOut, err := runSTMSnapshotDecode(snapshotDir, tc.sourceName)
			if err != nil {
				t.Fatalf("runSTMSnapshotDecode failed: %v", err)
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

func runSTMSnapshotDecode(snapshotDir, sourceName string) ([]byte, error) {
	out, err := runSTMSnapshotDecodeMode(snapshotDir, sourceName, false)
	if err == nil {
		return out, nil
	}
	return runSTMSnapshotDecodeMode(snapshotDir, sourceName, true)
}

func runSTMSnapshotDecodeMode(snapshotDir, sourceName string, forceSingle bool) ([]byte, error) {
	reader := snapshot.NewReader()
	reader.SetDir(snapshotDir)
	if err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %v", err)
	}

	if reader.ParsedTrace == nil {
		return nil, fmt.Errorf("missing parsed trace metadata")
	}

	sourceTree := snapshot.NewTraceBufferSourceTree()
	if !snapshot.ExtractSourceTree(sourceName, reader.ParsedTrace, sourceTree) || sourceTree.BufferInfo == nil {
		return nil, fmt.Errorf("failed to extract source tree for %s", sourceName)
	}

	dataFormat := strings.ToLower(sourceTree.BufferInfo.DataFormat)
	srcIsFrame := !forceSingle
	frameAlignment := 16
	if forceSingle || dataFormat == "source_data" {
		srcIsFrame = false
	} else if dataFormat == "dstream_coresight" {
		srcIsFrame = true
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

	stmDecoders := 0
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := testutil.FindParsedDeviceByName(reader.ParsedDeviceList, srcDevName)
		if dev == nil {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(dev.DeviceTypeName), "STM") {
			continue
		}

		cfg := stm.NewConfig()
		if val, ok := dev.RegValue("stmtcsr"); ok {
			cfg.RegTCSR = uint32(testutil.ParseHexOrDec(val))
		}

		traceID := cfg.TraceID()
		proc, dec, err := stm.NewConfiguredPipeline(int(traceID), cfg)
		if err != nil {
			return nil, fmt.Errorf("create STM pipeline for %s failed: %v", srcDevName, err)
		}

		if err := tree.AddWiredDecoder(traceID, ocsd.BuiltinDcdSTM, ocsd.ProtocolSTM, proc, dec, dec); err != nil {
			return nil, fmt.Errorf("attach STM decoder for %s failed: %v", srcDevName, err)
		}
		stmDecoders++
	}

	if stmDecoders == 0 {
		return nil, fmt.Errorf("no STM decoders found for source %s", sourceName)
	}

	var out bytes.Buffer
	printer := printers.NewGenericElementPrinter(&out)
	tree.SetGenTraceElemOutI(printer)
	tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
		proc, ok := elem.DataIn.(*stm.PktProc)
		if !ok || proc == nil {
			return
		}
		proc.SetPktRawMonitor(&stmRawPacketPrinter{writer: &out, traceID: csID})
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
			consumed, err := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:frameAlignment])
			resp := ocsd.DataRespFromErr(err)
			if ocsd.DataRespIsFatal(resp) {
				break
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
			consumed, err := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), remaining)
			resp := ocsd.DataRespFromErr(err)
			if ocsd.DataRespIsFatal(resp) {
				break
			}
			if consumed == 0 {
				return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			remaining = remaining[consumed:]
		}
	}

	_, err = tree.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(traceIndex), nil)
	resp := ocsd.DataRespFromErr(err)
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

		for _, idxLine := range testutil.SplitIdxRecords(line) {
			normalized := normalizeSnapshotLine(idxLine)
			if normalized == "" {
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

	out := make([]string, 0, len(parsed))
	for _, entry := range parsed {
		if _, ok := idSet[entry.id]; ok {
			out = append(out, entry.line)
		}
	}
	return strings.Join(out, "\n")
}

func normalizeSnapshotLine(line string) string {
	if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
		idx := strings.Index(line, "OCSD_GEN_TRC_ELEM_")
		if idx < 0 {
			return ""
		}
		elem := line[idx:]
		if strings.Contains(elem, "OCSD_GEN_TRC_ELEM_NO_SYNC") || strings.Contains(elem, "OCSD_GEN_TRC_ELEM_EO_TRACE") {
			return ""
		}
		return elem
	}

	_, right, ok := strings.Cut(line, "\t")
	if !ok {
		return ""
	}
	packetType := testutil.ExtractPacketType(strings.TrimSpace(right))
	if packetType == "" || packetType == "NOTSYNC" || packetType == "INCOMPLETE_EOT" {
		return ""
	}
	return packetType
}
