package etmv4_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv4"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
	"opencsd/internal/testutil"
)

type mapperAdapter struct {
	mapper memacc.Mapper
}

type etmv4RawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
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

func (p *etmv4RawPacketPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if p.writer == nil || op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	etmPkt, ok := pkt.(*etmv4.TracePacket)
	if !ok {
		return
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Idx:%d; ID:%x; [", indexSOP, p.traceID)
	for _, b := range rawData {
		fmt.Fprintf(&sb, "0x%02x ", b)
	}
	sb.WriteString("];\t")
	sb.WriteString(etmPkt.EffectiveType().String())
	sb.WriteString(" : description\n")
	_, _ = io.WriteString(p.writer, sb.String())
}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	buf := make([]byte, reqBytes)
	readBytes, err := m.mapper.Read(address, csTraceID, memSpace, reqBytes, buf)
	return readBytes, buf[:readBytes], err
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
				line, gotLine, wantLine := testutil.FirstDiff(gotLines, wantLines)

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

	etmv4Decoders := 0
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := testutil.FindParsedDeviceByName(reader.ParsedDeviceList, srcDevName)
		if dev == nil {
			continue
		}
		devType := strings.ToUpper(dev.DeviceTypeName)
		if !strings.HasPrefix(devType, "ETM4") {
			continue
		}

		cfg := &etmv4.Config{}
		_, _ = dev.RegValue("TRCTRACEIDR")

		var val string
		val, _ = dev.RegValue("TRCIDR0")
		cfg.RegIdr0 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR1")
		cfg.RegIdr1 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR2")
		cfg.RegIdr2 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR8")
		cfg.RegIdr8 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR9")
		cfg.RegIdr9 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR10")
		cfg.RegIdr10 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR11")
		cfg.RegIdr11 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR12")
		cfg.RegIdr12 = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCIDR13")
		cfg.RegIdr13 = uint32(testutil.ParseHexOrDec(val))

		val, _ = dev.RegValue("TRCCONFIGR")
		cfg.RegConfigr = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCTRACEIDR")
		cfg.RegTraceidr = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCVIPCSSCTLR")
		cfg.RegVipcssctlr = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCVINSTCCTLR")
		cfg.RegVinstcctlr = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCVIIECTLR")
		cfg.RegViiectlr = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCVISSCTLR")
		cfg.RegVissctlr = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCVIPCIECTLR")
		cfg.RegVipciectlr = uint32(testutil.ParseHexOrDec(val))
		val, _ = dev.RegValue("TRCVSEQR")
		cfg.RegVseqr = uint32(testutil.ParseHexOrDec(val))

		// Core architecture profile
		cfg.ArchVer = ocsd.ArchV8
		cfg.CoreProf = ocsd.ProfileCortexA

		var proc ocsd.TrcDataProcessorExplicit
		var dec *etmv4.PktDecode
		var applier common.FlagApplier
		var err error

		// Conditionally instantiate either the processor alone, or the full pipeline
		if packetOnly {
			var packetProc *etmv4.Processor
			packetProc, err = etmv4.NewConfiguredProcessor(cfg)
			proc = packetProc
			applier = packetProc
			// 'dec' remains nil
		} else {
			proc, dec, err = etmv4.NewConfiguredPipelineWithDeps(int(cfg.TraceID()), cfg, memIf, instr)
			applier = dec
		}

		if err != nil {
			return nil, fmt.Errorf("create ETMv4 pipeline for %s failed: %v", srcDevName, err)
		}

		// Inject into the DecodeTree.
		if dec == nil {
			err = tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV4I, ocsd.ProtocolETMV4I, proc, nil, applier)
		} else {
			err = tree.AddPullDecoder(cfg.TraceID(), ocsd.BuiltinDcdETMV4I, ocsd.ProtocolETMV4I, proc, dec, dec)
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
				if elem.FlagApplier != nil {
					_ = elem.FlagApplier.ApplyFlags(opts.extraOpFlags)
				}
			}
			if opts.instrRangeLimit > 0 {
				if dcd, ok := elem.FlagApplier.(*etmv4.PktDecode); ok {
					dcd.SetInstrRangeLimit(opts.instrRangeLimit)
				}
			}
		})
	}

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
				if err := mapper.AddAccessor(acc, 0); err != nil && !errors.Is(err, ocsd.ErrMemAccOverlap) {
					return nil, fmt.Errorf("add callback mem accessor failed for %s: %v", path, err)
				}
			} else {
				acc := memacc.NewBufferAccessor(ocsd.VAddr(memParams.Address), b)
				if err := mapper.AddAccessor(acc, 0); err != nil && !errors.Is(err, ocsd.ErrMemAccOverlap) {
					return nil, fmt.Errorf("add buffer mem accessor failed for %s: %v", path, err)
				}
			}
		}
	}

	var out bytes.Buffer
	printer := printers.NewGenericElementPrinter(&out)
	if !opts.suppressRawPackets {
		tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
			proc, ok := elem.DataIn.(*etmv4.Processor)
			if !ok || proc == nil {
				return
			}
			proc.SetPktRawMonitor(&etmv4RawPacketPrinter{writer: &out, traceID: csID})
		})
	}
	if err := drainAndPrintElements(tree, printer); err != nil {
		return nil, err
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
				consumed, ocsdErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), payload)
				resp := ocsd.DataRespFromErr(ocsdErr)
				if ocsd.DataRespIsFatal(resp) {
					return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v", resp, traceIndex, ocsdErr)
				}
				if consumed == 0 {
					return nil, fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
				}
				traceIndex += consumed
				payload = payload[consumed:]
				if err := drainAndPrintElements(tree, printer); err != nil {
					return nil, err
				}
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
			consumed, ocsdErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			resp := ocsd.DataRespFromErr(ocsdErr)
			if ocsd.DataRespIsFatal(resp) {
				return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v", resp, traceIndex, ocsdErr)
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
			consumed, ocsdErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), remaining)
			resp := ocsd.DataRespFromErr(ocsdErr)
			if ocsd.DataRespIsFatal(resp) {
				return nil, fmt.Errorf("fatal datapath response %d at trace index %d: %v", resp, traceIndex, ocsdErr)
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

	_, err = tree.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(traceIndex), nil)
	resp := ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		return nil, fmt.Errorf("fatal datapath response on EOT")
	}
	if err := drainAndPrintElements(tree, printer); err != nil {
		return nil, err
	}

	if opts.useCallbackMemAcc && callbackReads == 0 {
		return nil, fmt.Errorf("callback memory accessor was not exercised")
	}

	return out.Bytes(), nil
}

func drainAndPrintElements(tree *dcdtree.DecodeTree, printer *printers.GenericElementPrinter) error {
	if tree == nil || printer == nil {
		return nil
	}
	for {
		elem, err := tree.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if printErr := printer.PrintElement(elem); printErr != nil && !ocsd.IsDataWaitErr(printErr) {
			return printErr
		}
	}
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

		for _, idxLine := range testutil.SplitIdxRecords(line) {
			normalized := normalizeSnapshotLine(idxLine, includeGenElems)
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

	byID := make(map[string][]string, len(idSet))
	for _, entry := range parsed {
		if _, ok := idSet[entry.id]; ok {
			byID[entry.id] = append(byID[entry.id], entry.line)
		}
	}

	out := make([]string, 0, len(parsed))
	for _, rawID := range traceIDs {
		id := strings.ToLower(strings.TrimSpace(rawID))
		out = append(out, byID[id]...)
	}

	return strings.Join(out, "\n")
}

func normalizeSnapshotLine(line string, includeGenElems bool) string {
	if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
		if !includeGenElems {
			return ""
		}
		if strings.Contains(line, "OCSD_GEN_TRC_ELEM_NO_SYNC") {
			return ""
		}
		return line
	}
	if includeGenElems {
		return ""
	}

	left, right, ok := strings.Cut(line, "\t")
	if !ok {
		return ""
	}
	left = normalizeIdxPrefix(left)
	packetType := testutil.ExtractPacketType(strings.TrimSpace(right))
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
		dev := testutil.FindParsedDeviceByName(devs, srcDevName)
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
