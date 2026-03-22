package etmv4_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv4"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
)

type mapperAdapter struct {
	mapper memacc.Mapper
}

type etmv4RawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
}

type testErrLogger struct {
	lastErr *common.Error
}

type etmv4DecodeOptions struct {
	suppressRawPackets bool
	extraOpFlags       uint32
	instrRangeLimit    uint32
	useCallbackMemAcc  bool
}

type memRegionCallbackCtx struct {
	startAddr ocsd.VAddr
	data      []byte
	readCount *int
}

func makeMemRegionAccessCB(cbCtx *memRegionCallbackCtx) ocsd.MemAccessor {

	return func(address ocsd.VAddr, _ ocsd.MemSpaceAcc, reqBytes uint32, byteBuffer []byte) uint32 {
		if cbCtx == nil || len(cbCtx.data) == 0 {
			return 0
		}

		start := cbCtx.startAddr
		end := start + ocsd.VAddr(len(cbCtx.data)-1)
		if address < start || address > end {
			return 0
		}

		maxReadable := uint32(end-address) + 1
		readBytes := min(reqBytes, maxReadable)

		offset := int(address - start)
		copy(byteBuffer, cbCtx.data[offset:offset+int(readBytes)])
		if cbCtx.readCount != nil {
			(*cbCtx.readCount)++
		}
		return readBytes
	}
}

func (l *testErrLogger) LogError(_ ocsd.HandleErrLog, err *common.Error) {
	l.lastErr = err
}

func (l *testErrLogger) LogMessage(_ ocsd.HandleErrLog, _ ocsd.ErrSeverity, _ string) {}

func (l *testErrLogger) LastError() *common.Error          { return nil }
func (l *testErrLogger) LastIDError(_ uint8) *common.Error { return nil }

func (p *etmv4RawPacketPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *etmv4.TracePacket, rawData []byte) {
	if p.writer == nil || op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Idx:%d; ID:%x; [", indexSOP, p.traceID)
	for _, b := range rawData {
		fmt.Fprintf(&sb, "0x%02x ", b)
	}
	sb.WriteString("];\t")
	sb.WriteString(pkt.EffectiveType().String())
	sb.WriteString(" : description\n")
	_, _ = io.WriteString(p.writer, sb.String())
}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	buf := make([]byte, reqBytes)
	readBytes, err := m.mapper.Read(address, csTraceID, memSpace, reqBytes, buf)
	return readBytes, buf[:readBytes], ocsd.AsErr(err)
}

func (m *mapperAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

func TestETMv4SnapshotsAgainstGolden(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		snapshotName string
		sourceName   string
		traceIDs     []string
		packetOnly   bool // true for packet-level testing only (no full instruction decode)
		opts         etmv4DecodeOptions
	}{
		{name: "juno_r1_1", sourceName: "ETB_0", traceIDs: []string{"10", "11", "12", "13", "14", "15"}},
		{name: "juno_r1_1_rangelimit", snapshotName: "juno_r1_1", sourceName: "ETB_0", traceIDs: []string{"10", "11", "12", "13", "14", "15"}, opts: etmv4DecodeOptions{instrRangeLimit: 100}},
		{name: "juno_r1_1_badopcode", snapshotName: "juno_r1_1", sourceName: "ETB_0", traceIDs: []string{"10", "11", "12", "13", "14", "15"}, opts: etmv4DecodeOptions{extraOpFlags: ocsd.OpflgPktdecAA64OpcodeChk}},
		{name: "juno_r1_1_badopcode_flag", snapshotName: "juno_r1_1", sourceName: "ETB_0", traceIDs: []string{"10", "11", "12", "13", "14", "15"}, opts: etmv4DecodeOptions{extraOpFlags: ocsd.OpflgPktdecAA64OpcodeChk}},
		{name: "a57_single_step", sourceName: "CSTMC_TRACE_FIFO", traceIDs: []string{"10"}},
		{name: "armv8_1m_branches", sourceName: "etr_0", traceIDs: []string{"0"}},
		{name: "juno-uname-001", sourceName: "ETB_0", traceIDs: []string{"10"}},
		{name: "juno-uname-002", sourceName: "ETB_0", traceIDs: []string{"10", "12", "14", "16", "18", "1a"}},
		{name: "juno-ret-stck", sourceName: "ETB_0", traceIDs: []string{"10", "11", "12", "13", "14", "15"}},
		{name: "test-file-mem-offsets", sourceName: "ETB_0", traceIDs: []string{"16"}},
		{name: "init-short-addr", sourceName: "CSTMC_TRACE_FIFO", traceIDs: []string{"0"}},
		{name: "bugfix-exact-match", sourceName: "etr_0", traceIDs: []string{"10", "12", "14", "16", "18", "1a"}},
		{name: "a55-test-tpiu", sourceName: "DSTREAM_0", traceIDs: []string{"1"}, packetOnly: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			snapshotName := tc.name
			if tc.snapshotName != "" {
				snapshotName = tc.snapshotName
			}
			snapshotDir := filepath.Join("testdata", snapshotName)
			goldenPath := filepath.Join("testdata", tc.name+".ppl")
			if _, err := os.Stat(goldenPath); os.IsNotExist(err) {
				goldenPath = filepath.Join("testdata", tc.name+".ppl.gz")
			}

			goOut, err := runSnapshotDecode(snapshotDir, tc.sourceName, tc.packetOnly, tc.opts)
			if err != nil {
				t.Fatalf("runSnapshotDecode failed: %v", err)
			}

			goldenFile, err := os.Open(goldenPath)
			if err != nil {
				t.Fatalf("open golden file %s: %v", goldenPath, err)
			}
			defer goldenFile.Close()

			var goldenReader io.Reader = goldenFile
			if strings.HasSuffix(goldenPath, ".gz") {
				gzReader, err := gzip.NewReader(goldenFile)
				if err != nil {
					t.Fatalf("gzip reader for %s: %v", goldenPath, err)
				}
				defer gzReader.Close()
				goldenReader = gzReader
			}

			goldenBytes, err := io.ReadAll(goldenReader)
			if err != nil {
				t.Fatalf("read golden file %s: %v", goldenPath, err)
			}

			includeGenElems := strings.Contains(string(goldenBytes), "OCSD_GEN_TRC_ELEM_")
			got := sanitizePPL(string(goOut), tc.traceIDs, includeGenElems)
			want := sanitizePPL(string(goldenBytes), tc.traceIDs, includeGenElems)
			// os.WriteFile("got.txt", []byte(got), 0644)

			if got != want {
				gotLines := strings.Split(got, "\n")
				wantLines := strings.Split(want, "\n")
				line, gotLine, wantLine := firstDiff(gotLines, wantLines)

				// Write context around diff to help debugging
				const ctx = 5
				startCtx := max(line-1-ctx, 0)
				endCtx := line - 1 + ctx
				t.Logf("=== Context around first diff (line %d) ===", line)
				for i := startCtx; i < endCtx; i++ {
					marker := " "
					if i == line-1 {
						marker = ">"
					}
					wl := ""
					if i < len(wantLines) {
						wl = wantLines[i]
					}
					gl := ""
					if i < len(gotLines) {
						gl = gotLines[i]
					}
					if wl == gl {
						t.Logf("%s %3d MATCH: %s", marker, i+1, wl)
					} else {
						t.Logf("%s %3d WANT: %s", marker, i+1, wl)
						t.Logf("%s %3d  GOT: %s", marker, i+1, gl)
					}
				}
				t.Logf("=== want total: %d lines, got total: %d lines ===", len(wantLines), len(gotLines))

				t.Fatalf("snapshot mismatch at line %d\nwant: %s\n got: %s", line, wantLine, gotLine)
			}
		})
	}
}

func TestETMv4MemBuffDemoBehavior(t *testing.T) {
	t.Parallel()

	t.Run("mem_buff_demo", func(t *testing.T) {
		t.Parallel()
		out, err := runSnapshotDecode(filepath.Join("testdata", "juno_r1_1"), "ETB_0", false, etmv4DecodeOptions{suppressRawPackets: true})
		if err != nil {
			t.Fatalf("buffer memacc decode failed: %v", err)
		}
		if len(bytes.TrimSpace(out)) == 0 {
			t.Fatalf("buffer memacc decode produced no output")
		}
	})

	t.Run("mem_buff_demo_cb", func(t *testing.T) {
		t.Parallel()
		out, err := runSnapshotDecode(filepath.Join("testdata", "juno_r1_1"), "ETB_0", false, etmv4DecodeOptions{suppressRawPackets: true, useCallbackMemAcc: true})
		if err != nil {
			t.Fatalf("callback memacc decode failed: %v", err)
		}
		if len(bytes.TrimSpace(out)) == 0 {
			t.Fatalf("callback memacc decode produced no output")
		}
	})
}

func runSnapshotDecode(snapshotDir, sourceName string, packetOnly bool, opts etmv4DecodeOptions) ([]byte, error) {
	reader := snapshot.NewReader()
	reader.SetDir(snapshotDir)
	if err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	if reader.ParsedTrace == nil {
		return nil, fmt.Errorf("missing parsed trace metadata")
	}

	resolvedSourceName := resolveETMv4SourceName(sourceName, reader.ParsedTrace, reader.ParsedDeviceList)
	if resolvedSourceName == "" {
		return nil, fmt.Errorf("failed to resolve ETMv4 source tree for %s", sourceName)
	}

	sourceTree := snapshot.NewTraceBufferSourceTree()
	if !snapshot.ExtractSourceTree(resolvedSourceName, reader.ParsedTrace, sourceTree) || sourceTree.BufferInfo == nil {
		return nil, fmt.Errorf("failed to extract source tree for %s", resolvedSourceName)
	}

	dataFormat := strings.ToLower(sourceTree.BufferInfo.DataFormat)
	srcIsFrame := true
	frameAlignment := 16
	dstreamFormat := false
	switch dataFormat {
	case "source_data":
		srcIsFrame = false
	case "dstream_coresight":
		frameAlignment = 4
		dstreamFormat = true
	}

	formatterFlags := uint32(ocsd.DfrmtrFrameMemAlign)
	if dstreamFormat {
		formatterFlags = ocsd.DfrmtrHasFsyncs
	}

	srcType := ocsd.TrcSrcFrameFormatted
	if !srcIsFrame {
		srcType = ocsd.TrcSrcSingle
	}

	tree := dcdtree.NewDefaultDecodeTree(srcType, formatterFlags)
	if tree == nil {
		return nil, fmt.Errorf("nil decode tree")
	}

	errLog := &testErrLogger{}
	if df := tree.FrameDeformatter(); df != nil {
		df.SetErrorLogger(errLog)
	}

	etmv4Decoders := 0
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := findParsedDeviceByName(reader.ParsedDeviceList, srcDevName)
		if dev == nil {
			continue
		}
		devType := strings.ToUpper(dev.DeviceTypeName)
		if !strings.HasPrefix(devType, "ETM4") {
			continue
		}

		cfg := &etmv4.Config{}
		var val string
		val, _ = dev.RegValue("TRCTRACEIDR")

		val, _ = dev.RegValue("TRCIDR0")
		cfg.RegIdr0 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR1")
		cfg.RegIdr1 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR2")
		cfg.RegIdr2 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR8")
		cfg.RegIdr8 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR9")
		cfg.RegIdr9 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR10")
		cfg.RegIdr10 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR11")
		cfg.RegIdr11 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR12")
		cfg.RegIdr12 = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR13")
		cfg.RegIdr13 = uint32(parseHexOrDec(val))

		val, _ = dev.RegValue("TRCCONFIGR")
		cfg.RegConfigr = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCTRACEIDR")
		cfg.RegTraceidr = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCVIPCSSCTLR")
		cfg.RegVipcssctlr = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCVINSTCCTLR")
		cfg.RegVinstcctlr = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCVIIECTLR")
		cfg.RegViiectlr = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCVISSCTLR")
		cfg.RegVissctlr = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCVIPCIECTLR")
		cfg.RegVipciectlr = uint32(parseHexOrDec(val))
		val, _ = dev.RegValue("TRCVSEQR")
		cfg.RegVseqr = uint32(parseHexOrDec(val))

		// Core architecture profile
		cfg.ArchVer = ocsd.ArchV8
		cfg.CoreProf = ocsd.ProfileCortexA

		var err error
		if packetOnly {
			err = tree.CreatePacketProcessor(ocsd.BuiltinDcdETMV4I, cfg)
		} else {
			err = tree.CreateFullDecoder(ocsd.BuiltinDcdETMV4I, cfg)
		}

		if err != nil {
			return nil, fmt.Errorf("create ETMv4 decoder for %s failed: %v", srcDevName, err)
		}
		etmv4Decoders++
	}

	if etmv4Decoders == 0 {
		return nil, fmt.Errorf("no ETMv4 decoders found for source %s", resolvedSourceName)
	}

	if opts.extraOpFlags != 0 || opts.instrRangeLimit > 0 {
		tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
			if elem == nil {
				return
			}
			if opts.extraOpFlags != 0 {
				if opComp, ok := elem.DecoderHandle.(interface {
					ConfigureComponentOpMode(uint32) ocsd.Err
					ComponentOpMode() uint32
					SupportedOpModes() uint32
				}); ok {
					flags := opts.extraOpFlags & opComp.SupportedOpModes()
					if flags != 0 {
						_ = opComp.ConfigureComponentOpMode(opComp.ComponentOpMode() | flags)
					}
				}
			}
			if opts.instrRangeLimit > 0 {
				if dcd, ok := elem.DecoderHandle.(*etmv4.PktDecode); ok {
					dcd.SetInstrRangeLimit(opts.instrRangeLimit)
				}
			}
		})
	}

	mapper := memacc.NewGlobalMapper()
	tree.SetMemAccessI(&mapperAdapter{mapper: mapper})
	callbackReads := 0

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

			if opts.useCallbackMemAcc {
				startAddr := ocsd.VAddr(memParams.Address)
				endAddr := startAddr + ocsd.VAddr(len(b)-1)
				cbCtx := &memRegionCallbackCtx{startAddr: startAddr, data: b, readCount: &callbackReads}
				acc := memacc.NewCallbackAccessor(startAddr, endAddr, ocsd.MemSpaceAny)
				acc.SetCallback(makeMemRegionAccessCB(cbCtx))
				if err := mapper.AddAccessor(acc, 0); err != ocsd.OK && err != ocsd.ErrMemAccOverlap {
					return nil, fmt.Errorf("add callback mem accessor failed for %s: %v", path, err)
				}
			} else {
				acc := memacc.NewBufferAccessor(ocsd.VAddr(memParams.Address), b)
				if err := mapper.AddAccessor(acc, 0); err != ocsd.OK && err != ocsd.ErrMemAccOverlap {
					return nil, fmt.Errorf("add buffer mem accessor failed for %s: %v", path, err)
				}
			}
		}
	}

	var out bytes.Buffer
	printer := printers.NewGenericElementPrinter(&out)
	tree.SetGenTraceElemOutI(printer)
	if !opts.suppressRawPackets {
		tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
			proc, ok := elem.DataIn.(*etmv4.Processor)
			if !ok || proc == nil {
				return
			}
			proc.SetPktRawMonitor(&etmv4RawPacketPrinter{writer: &out, traceID: csID})
		})
	}

	binFile := filepath.Join(snapshotDir, sourceTree.BufferInfo.DataFileName)
	traceData, err := os.ReadFile(binFile)
	if err != nil {
		return nil, fmt.Errorf("read trace buffer %s: %w", binFile, err)
	}

	var traceIndex uint32
	if dstreamFormat {
		remaining := traceData
		for len(remaining) > 0 {
			payloadLen := min(len(remaining), 504)
			payload := remaining[:payloadLen]

			for len(payload) > 0 {
				consumed, resp, ocsdErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), payload)
				if ocsd.DataRespIsFatal(resp) {
					if errLog.lastErr != nil {
						return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v (%s)", resp, traceIndex, ocsdErr, errLog.lastErr)
					}
					return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v", resp, traceIndex, ocsdErr)
				}
				if consumed == 0 {
					return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
				}
				traceIndex += consumed
				payload = payload[consumed:]
			}

			remaining = remaining[payloadLen:]
			footerLen := min(len(remaining), 8)
			remaining = remaining[footerLen:]
		}
	} else if srcIsFrame {
		pending := traceData
		for len(pending) >= frameAlignment {
			sendLen := len(pending) - (len(pending) % frameAlignment)
			const maxChunk = 256
			if sendLen > maxChunk {
				sendLen = maxChunk - (maxChunk % frameAlignment)
			}
			consumed, resp, ocsdErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			if ocsd.DataRespIsFatal(resp) {
				if errLog.lastErr != nil {
					return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v (%s)", resp, traceIndex, ocsdErr, errLog.lastErr)
				}
				return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v", resp, traceIndex, ocsdErr)
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
			consumed, resp, ocsdErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), remaining)
			if ocsd.DataRespIsFatal(resp) {
				if errLog.lastErr != nil {
					return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v (%s)", resp, traceIndex, ocsdErr, errLog.lastErr)
				}
				return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v", resp, traceIndex, ocsdErr)
			}
			if consumed == 0 {
				return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			remaining = remaining[consumed:]
		}
	}

	_, resp, _ := tree.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(traceIndex), nil)
	if ocsd.DataRespIsFatal(resp) {
		return nil, fmt.Errorf("fatal datapath response on EOT")
	}

	if opts.useCallbackMemAcc && callbackReads == 0 {
		return nil, fmt.Errorf("callback memory accessor was not exercised")
	}

	return out.Bytes(), nil
}

func sanitizePPL(s string, traceIDs []string, includeGenElems bool) string {
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
			normalized := normalizeSnapshotLine(idxLine, includeGenElems)
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

func normalizeSnapshotLine(line string, includeGenElems bool) string {
	if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
		if !includeGenElems {
			return ""
		}
		return line
	}

	left, right, ok := strings.Cut(line, "\t")
	if !ok {
		return ""
	}
	left = normalizeIdxPrefix(left)
	packetType := extractPacketType(strings.TrimSpace(right))
	if packetType == "" {
		return ""
	}
	return strings.TrimSpace(left) + "\t" + packetType
}

func normalizeIdxPrefix(left string) string {
	trimmed := strings.TrimSpace(left)
	if !strings.HasPrefix(trimmed, "Idx:") {
		return trimmed
	}

	parts := strings.Split(trimmed, ";")
	if len(parts) < 2 {
		return trimmed
	}
	idxPart := strings.TrimSpace(parts[0])
	idPart := strings.TrimSpace(parts[1])
	if !strings.HasPrefix(idPart, "ID:") {
		return trimmed
	}

	return fmt.Sprintf("%s; %s;", idxPart, idPart)
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

func resolveETMv4SourceName(requested string, trace *snapshot.ParsedTrace, devs map[string]*snapshot.ParsedDevice) string {
	candidates := make([]string, 0, len(trace.TraceBuffers)+1)
	if strings.TrimSpace(requested) != "" {
		candidates = append(candidates, strings.TrimSpace(requested))
	}
	for _, info := range trace.TraceBuffers {
		if strings.TrimSpace(info.BufferName) == "" {
			continue
		}
		candidates = append(candidates, info.BufferName)
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		tree := snapshot.NewTraceBufferSourceTree()
		if !snapshot.ExtractSourceTree(candidate, trace, tree) || tree.BufferInfo == nil {
			continue
		}
		if sourceTreeHasETMv4Devices(tree, devs) {
			return candidate
		}
	}
	return ""
}

func sourceTreeHasETMv4Devices(sourceTree *snapshot.TraceBufferSourceTree, devs map[string]*snapshot.ParsedDevice) bool {
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := findParsedDeviceByName(devs, srcDevName)
		if dev == nil {
			continue
		}
		devType := strings.ToUpper(dev.DeviceTypeName)
		if strings.HasPrefix(devType, "ETM4") {
			return true
		}
	}
	return false
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
