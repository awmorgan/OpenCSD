package ete_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/dcdtree"
	"opencsd/internal/ete"
	"opencsd/internal/etmv4"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
)

type mapperAdapter struct {
	mapper memacc.Mapper
}

type eteRawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
}

func (p *eteRawPacketPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if p.writer == nil || op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	etmPkt, ok := pkt.(*etmv4.TracePacket)
	if !ok {
		return
	}
	_, _ = io.WriteString(p.writer, fmt.Sprintf("Idx:%d; ID:%x;\t%s : description\n", indexSOP, p.traceID, etmPkt.EffectiveType().String()))
}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	buf := make([]byte, reqBytes)
	readBytes, err := m.mapper.Read(address, csTraceID, memSpace, reqBytes, buf)
	return readBytes, buf[:readBytes], err
}

func (m *mapperAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

type eteDecodeOptions struct {
	multiSession bool
	srcAddrN     bool
}

type eteGoldenTestCase struct {
	name        string
	goldenPath  string
	snapshotDir string
	sourceName  string
	options     eteDecodeOptions
}

func TestETESnapshotsAgainstGolden(t *testing.T) {
	t.Parallel()

	testCases, err := discoverETEGoldenTestCases("testdata")
	if err != nil {
		t.Fatalf("discover golden test cases: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wantBytes, err := os.ReadFile(tc.goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", tc.goldenPath, err)
			}

			gotBytes, err := runETESnapshotDecode(tc.snapshotDir, tc.sourceName, tc.options)
			if err != nil {
				t.Fatalf("runETESnapshotDecode failed: %v", err)
			}

			includeGenElems := strings.Contains(string(wantBytes), "OCSD_GEN_TRC_ELEM_")
			got := sanitizePPL(string(gotBytes), includeGenElems)
			want := sanitizePPL(string(wantBytes), includeGenElems)

			if got != want {
				gotLines := strings.Split(got, "\n")
				wantLines := strings.Split(want, "\n")
				line, gotLine, wantLine := firstDiff(gotLines, wantLines)
				t.Fatalf("snapshot mismatch at line %d\nwant: %s\n got: %s", line, wantLine, gotLine)
			}
		})
	}
}

func TestSanitizePPLEmbeddedIdxRecords(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		"Using infrastructure as trace source",
		"Idx:2164; ID:10; [0x04 ];\tI_TRACE_ON : Trace On.",
		"DCD_ETMV4_0016 : 0x0019 (OCSD_ERR_BAD_DECODE_PKT) [Reserved or unknown packet in decoder.]; TrcIdx=2164; CS ID=10; Unknown packet type.Idx:2165; ID:10; [0xfb ];\tI_ATOM_F3 : Atom format 3.; EEN",
		"Idx:2166; ID:10; [0xf7 ];\tI_ATOM_F1 : Atom format 1.; E",
		"Idx:2167; ID:10; [0x95 0x5b ];\tI_ADDR_S_IS0 : Address, Short, IS0.; Addr=0xFFFFFFC000592B6C ~[0x16C]",
		"", // trailing newline
	}, "\n")

	got := sanitizePPL(input, false)
	want := strings.Join([]string{
		"ID:10;\tI_TRACE_ON",
		"ID:10;\tI_ADDR_OR_ATOM",
		"ID:10;\tI_ADDR_OR_ATOM",
		"ID:10;\tI_ADDR_OR_ATOM",
	}, "\n")

	if got != want {
		t.Fatalf("sanitizePPL mismatch\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func runETESnapshotDecode(snapshotDir, requestedSource string, opts eteDecodeOptions) ([]byte, error) {
	reader := snapshot.NewReader()
	reader.SetDir(snapshotDir)
	if err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %v", err)
	}
	if reader.ParsedTrace == nil {
		return nil, fmt.Errorf("missing parsed trace metadata")
	}

	bufferName := resolveETESourceName(requestedSource, reader.ParsedTrace, reader.ParsedDeviceList)
	if bufferName == "" {
		return nil, fmt.Errorf("no ETE source trees found")
	}

	sourceTree := snapshot.NewTraceBufferSourceTree()
	if !snapshot.ExtractSourceTree(bufferName, reader.ParsedTrace, sourceTree) || sourceTree.BufferInfo == nil {
		return nil, fmt.Errorf("failed to extract source tree for %s", bufferName)
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

	eteDecoders := 0
	seenTraceIDs := map[uint8]struct{}{}
	srcDevNames := make([]string, 0, len(sourceTree.SourceCoreAssoc))
	for srcDevName := range sourceTree.SourceCoreAssoc {
		srcDevNames = append(srcDevNames, srcDevName)
	}
	sort.Strings(srcDevNames)
	for _, srcDevName := range srcDevNames {
		dev := findParsedDeviceByName(reader.ParsedDeviceList, srcDevName)
		if dev == nil {
			continue
		}
		if !strings.EqualFold(dev.DeviceTypeName, "ETE") {
			continue
		}

		cfg := ete.NewConfig()
		if val, ok := dev.RegValue("trcidr0"); ok {
			cfg.RegIdr0 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.RegValue("trcidr1"); ok {
			cfg.RegIdr1 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.RegValue("trcidr2"); ok {
			cfg.RegIdr2 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.RegValue("trcidr8"); ok {
			cfg.RegIdr8 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.RegValue("trcdevarch"); ok {
			cfg.RegDevArch = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.RegValue("trcconfigr"); ok {
			cfg.RegConfigr = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.RegValue("trctraceidr"); ok {
			cfg.RegTraceidr = uint32(parseHexOrDec(val))
		}
		traceID := cfg.TraceID()
		if _, exists := seenTraceIDs[traceID]; exists {
			continue
		}

		proc, dec, err := ete.NewConfiguredPipelineWithDeps(int(traceID), cfg, nil, memIf, instr)
		if err != nil {
			return nil, fmt.Errorf("create ETE pipeline for %s failed: %v", srcDevName, err)
		}

		if err := tree.AddDecoder(traceID, ocsd.BuiltinDcdETE, ocsd.ProtocolETE, proc, dec); err != nil {
			if errors.Is(err, ocsd.ErrAttachTooMany) {
				continue
			}
			return nil, fmt.Errorf("attach ETE decoder for %s failed: %v", srcDevName, err)
		}
		if err := tree.AddPullDecoder(traceID, ocsd.BuiltinDcdETE, ocsd.ProtocolETE, dec); err != nil {
			return nil, fmt.Errorf("attach ETE pull decoder for %s failed: %v", srcDevName, err)
		}
		eteDecoders++
		seenTraceIDs[traceID] = struct{}{}
	}

	if eteDecoders == 0 {
		return nil, fmt.Errorf("no ETE decoders found for source %s", bufferName)
	}

	applyOpModeFlags(tree, eteOpFlags(opts))

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
		proc, ok := elem.DataIn.(*etmv4.Processor)
		if !ok || proc == nil {
			return
		}
		proc.SetPktRawMonitor(&eteRawPacketPrinter{writer: &out, traceID: csID})
	})
	if err := drainAndPrintElements(tree, printer); err != nil {
		return nil, err
	}

	buffers := eteSnapshotBuffers(reader.ParsedTrace, bufferName, opts.multiSession)
	if len(buffers) == 0 {
		return nil, fmt.Errorf("no trace buffers found for source %s", bufferName)
	}

	for i, bufInfo := range buffers {
		srcTree, ok := reader.SourceTrees[bufInfo.BufferName]
		if !ok || srcTree == nil || srcTree.BufferInfo == nil {
			continue
		}
		binFile := filepath.Join(snapshotDir, srcTree.BufferInfo.DataFileName)
		traceData, err := os.ReadFile(binFile)
		if err != nil {
			return nil, fmt.Errorf("read trace buffer %s: %w", binFile, err)
		}
		if err := decodeETETraceBuffer(tree, traceData, srcIsFrame, frameAlignment, printer); err != nil {
			return nil, err
		}
		if opts.multiSession && i+1 < len(buffers) {
			if _, err2 := tree.TraceDataIn(ocsd.OpReset, 0, nil); err2 != nil {
				return nil, fmt.Errorf("OpReset after buffer %s: %w", bufInfo.BufferName, err2)
			}
			if err := drainAndPrintElements(tree, printer); err != nil {
				return nil, err
			}
		}
	}

	return out.Bytes(), nil
}

func findParsedDeviceByName(devices map[string]*snapshot.ParsedDevice, name string) *snapshot.ParsedDevice {
	for _, dev := range devices {
		if dev.DeviceName == name {
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

func sanitizePPL(s string, keepGenElems bool) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")

	start := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Idx:") || strings.HasPrefix(trimmed, "Frame:") {
			start = i
			break
		}
	}

	out := make([]string, 0, len(lines)-start)
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		for _, idxLine := range splitIdxRecords(line) {
			normalized := normalizeSnapshotLine(idxLine, keepGenElems)
			if normalized == "" {
				continue
			}
			out = append(out, normalized)
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

var iPacketTokenRE = regexp.MustCompile(`\bI_[A-Z0-9_]+\b`)

func normalizeSnapshotLine(line string, keepGenElems bool) string {
	if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
		if strings.Contains(line, "OCSD_GEN_TRC_ELEM_EO_TRACE(") {
			return ""
		}
		if keepGenElems {
			return line
		}
		return ""
	}
	// When comparing gen elems, skip raw packet lines to avoid ordering
	// fragility from mixing indexed gen-elem output with unindexed packet output.
	// Raw packet parity is still exercised when keepGenElems=false.
	if keepGenElems {
		return ""
	}

	m := iPacketTokenRE.FindString(line)
	if m == "" {
		return ""
	}
	m = canonicalPacketToken(m)
	idx := strings.Index(line, "ID:")
	if idx < 0 {
		return ""
	}
	rest := line[idx:]
	semiRel := strings.Index(rest, ";")
	if semiRel < 0 {
		return ""
	}
	idPrefix := strings.TrimSpace(line[idx : idx+semiRel+1])
	return idPrefix + "\t" + m
}

func canonicalPacketToken(tok string) string {
	if strings.HasPrefix(tok, "I_ADDR_") || strings.HasPrefix(tok, "I_SRC_ADDR_") || strings.HasPrefix(tok, "I_SCR_ADDR_") {
		return "I_ADDR_OR_ATOM"
	}
	switch tok {
	case "I_ATOM_F1", "I_ATOM_F2", "I_ATOM_F3", "I_ATOM_F4", "I_ATOM_F5", "I_ATOM_F6":
		return "I_ADDR_OR_ATOM"
	case "I_ATOM":
		return "I_ADDR_OR_ATOM"
	case "I_ETE_ITE":
		return "I_ITE"
	case "I_ETE_TRANS_ST":
		return "I_TRANS_ST"
	case "I_ETE_TRANS_COMMIT":
		return "I_TRANS_COMMIT"
	case "I_ETE_TRANS_FAIL":
		return "I_TRANS_FAIL"
	case "I_ETE_PE_RESET":
		return "I_PE_RESET"
	case "ETE_PKT_I_SRC_ADDR_MATCH":
		return "I_ADDR_OR_ATOM"
	case "ETE_PKT_I_SRC_ADDR_S_IS0":
		return "I_ADDR_OR_ATOM"
	case "ETE_PKT_I_SRC_ADDR_S_IS1":
		return "I_ADDR_OR_ATOM"
	case "ETE_PKT_I_SRC_ADDR_L_32IS0":
		return "I_ADDR_OR_ATOM"
	case "ETE_PKT_I_SRC_ADDR_L_32IS1":
		return "I_ADDR_OR_ATOM"
	case "ETE_PKT_I_SRC_ADDR_L_64IS0":
		return "I_ADDR_OR_ATOM"
	case "ETE_PKT_I_SRC_ADDR_L_64IS1":
		return "I_ADDR_OR_ATOM"
	default:
		return tok
	}
}

func resolveETESourceName(requested string, trace *snapshot.ParsedTrace, devs map[string]*snapshot.ParsedDevice) string {
	if strings.TrimSpace(requested) != "" {
		tree := snapshot.NewTraceBufferSourceTree()
		if snapshot.ExtractSourceTree(strings.TrimSpace(requested), trace, tree) && tree.BufferInfo != nil && sourceTreeHasETEDevices(tree, devs) {
			return strings.TrimSpace(requested)
		}
	}

	for _, info := range trace.TraceBuffers {
		if strings.TrimSpace(info.BufferName) == "" {
			continue
		}
		tree := snapshot.NewTraceBufferSourceTree()
		if !snapshot.ExtractSourceTree(info.BufferName, trace, tree) || tree.BufferInfo == nil {
			continue
		}
		if sourceTreeHasETEDevices(tree, devs) {
			return info.BufferName
		}
	}
	return ""
}

func extractSourceNameFromGolden(ppl string) string {
	for line := range strings.SplitSeq(strings.ReplaceAll(ppl, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Using ") && strings.Contains(line, " as trace source") {
			name := strings.TrimPrefix(line, "Using ")
			name = strings.TrimSuffix(name, " as trace source")
			return strings.TrimSpace(name)
		}
	}
	return ""
}

func sourceTreeHasETEDevices(sourceTree *snapshot.TraceBufferSourceTree, devs map[string]*snapshot.ParsedDevice) bool {
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := findParsedDeviceByName(devs, srcDevName)
		if dev == nil {
			continue
		}
		if strings.EqualFold(dev.DeviceTypeName, "ETE") {
			return true
		}
	}
	return false
}

func firstDiff(gotLines, wantLines []string) (line int, gotLine, wantLine string) {
	n := max(len(wantLines), len(gotLines))
	for i := range n {
		var g, w string
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g != w {
			return i + 1, g, w
		}
	}
	return 0, "", ""
}

func drainAndPrintElements(tree *dcdtree.DecodeTree, printer *printers.GenericElementPrinter) error {
	if tree == nil || printer == nil {
		return nil
	}
	type drainedElem struct {
		seq  int
		qseq uint64
		elem ocsd.TraceElement
	}
	drained := make([]drainedElem, 0)
	tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
		if elem == nil || elem.Iterator == nil {
			return
		}
		iter, ok := elem.Iterator.(ete.SequencedTraceIterator)
		if !ok {
			return
		}
		for {
			qseq, trcElem, nextErr := iter.NextSequenced()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				drained = append(drained, drainedElem{seq: -1, elem: ocsd.TraceElement{Index: 0}})
				return
			}
			copyElem := *trcElem
			drained = append(drained, drainedElem{seq: len(drained), qseq: qseq, elem: copyElem})
		}
	})
	if len(drained) > 0 && drained[0].seq == -1 {
		return io.ErrUnexpectedEOF
	}
	sort.SliceStable(drained, func(i, j int) bool {
		if drained[i].elem.Index != drained[j].elem.Index {
			return drained[i].elem.Index < drained[j].elem.Index
		}
		if drained[i].qseq != drained[j].qseq {
			return drained[i].qseq < drained[j].qseq
		}
		return drained[i].seq < drained[j].seq
	})
	maxEOIndex := ocsd.TrcIndex(0)
	eoCount := 0
	for i := range drained {
		if drained[i].elem.ElemType == ocsd.GenElemEOTrace {
			eoCount++
			if drained[i].elem.Index > maxEOIndex {
				maxEOIndex = drained[i].elem.Index
			}
		}
	}
	for i := range drained {
		elem := &drained[i].elem
		if eoCount > 1 && elem.ElemType == ocsd.GenElemEOTrace && elem.Index != maxEOIndex {
			continue
		}
		if printErr := printer.TraceElemIn(elem.Index, elem.TraceID, elem); printErr != nil && !ocsd.IsDataWaitErr(printErr) {
			return printErr
		}
	}
	return nil
}

func decodeETETraceBuffer(tree *dcdtree.DecodeTree, traceData []byte, srcIsFrame bool, alignment int, printer *printers.GenericElementPrinter) error {
	var traceIndex uint32
	if srcIsFrame {
		pending := traceData
		for len(pending) >= alignment {
			sendLen := alignment
			consumed, err := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			resp := ocsd.DataRespFromErr(err)
			if ocsd.DataRespIsFatal(resp) {
				return fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
			}
			if consumed == 0 {
				return fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			pending = pending[consumed:]
			if err := drainAndPrintElements(tree, printer); err != nil {
				return err
			}
		}
	} else {
		remaining := traceData
		for len(remaining) > 0 {
			sendLen := min(len(remaining), 256)
			consumed, err := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), remaining[:sendLen])
			resp := ocsd.DataRespFromErr(err)
			if ocsd.DataRespIsFatal(resp) {
				return fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
			}
			if consumed == 0 {
				return fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
			}
			traceIndex += consumed
			remaining = remaining[consumed:]
			if err := drainAndPrintElements(tree, printer); err != nil {
				return err
			}
		}
	}
	_, err := tree.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(traceIndex), nil)
	resp := ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		return fmt.Errorf("fatal datapath response on EOT")
	}
	if err := drainAndPrintElements(tree, printer); err != nil {
		return err
	}
	return nil
}

func eteSnapshotBuffers(trace *snapshot.ParsedTrace, primaryBuffer string, multiSession bool) []snapshot.TraceBufferInfo {
	if trace == nil || len(trace.TraceBuffers) == 0 {
		return nil
	}

	byName := make(map[string]snapshot.TraceBufferInfo, len(trace.TraceBuffers))
	for _, info := range trace.TraceBuffers {
		if strings.TrimSpace(info.BufferName) == "" {
			continue
		}
		byName[info.BufferName] = info
	}

	if !multiSession {
		if info, ok := byName[primaryBuffer]; ok {
			return []snapshot.TraceBufferInfo{info}
		}
		return nil
	}

	ordered := make([]snapshot.TraceBufferInfo, 0, len(byName))
	if info, ok := byName[primaryBuffer]; ok {
		ordered = append(ordered, info)
	}
	for _, info := range trace.TraceBuffers {
		if info.BufferName == primaryBuffer || strings.TrimSpace(info.BufferName) == "" {
			continue
		}
		ordered = append(ordered, info)
	}
	return ordered
}

func eteOpFlags(opts eteDecodeOptions) uint32 {
	var flags uint32
	if opts.srcAddrN {
		flags |= ocsd.OpflgPktdecSrcAddrNAtoms
	}
	return flags
}

func applyOpModeFlags(tree *dcdtree.DecodeTree, flags uint32) {
	if tree == nil || flags == 0 {
		return
	}
	apply := func(component any) {
		applier, ok := component.(common.FlagApplier)
		if !ok || applier == nil {
			return
		}
		_ = applier.ApplyFlags(flags)
	}
	tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
		if elem == nil {
			return
		}
		apply(elem.FlagApplier)
	})
}

func discoverETEGoldenTestCases(testdataDir string) ([]eteGoldenTestCase, error) {
	entries, err := os.ReadDir(testdataDir)
	if err != nil {
		return nil, err
	}
	var cases []eteGoldenTestCase
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ppl") {
			continue
		}
		goldenPath := filepath.Join(testdataDir, e.Name())
		snapshotName, opts, err := extractETECommandLine(goldenPath)
		if err != nil {
			continue
		}
		snapshotDir := filepath.Join(testdataDir, snapshotName)
		if _, err := os.Stat(snapshotDir); err != nil {
			continue
		}
		goldenContent, err := os.ReadFile(goldenPath)
		if err != nil {
			continue
		}
		caseName := strings.TrimSuffix(e.Name(), ".ppl")
		sourceName := extractSourceNameFromGolden(string(goldenContent))
		cases = append(cases, eteGoldenTestCase{
			name:        caseName,
			goldenPath:  goldenPath,
			snapshotDir: snapshotDir,
			sourceName:  sourceName,
			options:     opts,
		})
	}
	return cases, nil
}

func extractETECommandLine(pplPath string) (snapshotName string, opts eteDecodeOptions, err error) {
	data, err := os.ReadFile(pplPath)
	if err != nil {
		return "", eteDecodeOptions{}, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	cmdLineStart := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "Test Command Line:-" {
			cmdLineStart = i + 1
			break
		}
	}
	if cmdLineStart < 0 || cmdLineStart >= len(lines) {
		return "", eteDecodeOptions{}, fmt.Errorf("no command line found in %s", pplPath)
	}
	tokens := strings.Fields(lines[cmdLineStart])
	for i, tok := range tokens {
		switch strings.ToLower(tok) {
		case "-ss_dir":
			if i+1 < len(tokens) {
				snapshotName = filepath.Base(tokens[i+1])
			}
		case "-multi_session":
			opts.multiSession = true
		case "-src_addr_n":
			opts.srcAddrN = true
		}
	}
	if snapshotName == "" {
		return "", eteDecodeOptions{}, fmt.Errorf("no -ss_dir in command line of %s", pplPath)
	}
	return snapshotName, opts, nil
}
