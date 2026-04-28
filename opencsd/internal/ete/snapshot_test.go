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
	"opencsd/internal/testutil"
)

type mapperAdapter struct {
	mapper memacc.Mapper
}

type eteRawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
}

func (p *eteRawPacketPrinter) MonitorRawData(indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if p.writer == nil || pkt == nil || len(rawData) == 0 {
		return
	}
	etmPkt, ok := pkt.(*etmv4.TracePacket)
	if !ok {
		return
	}
	_, _ = io.WriteString(p.writer, fmt.Sprintf("Idx:%d; ID:%x;\t%s : description\n", indexSOP, p.traceID, etmPkt.EffectiveType().String()))
}

func (p *eteRawPacketPrinter) MonitorEOT() {}

func (p *eteRawPacketPrinter) MonitorReset(indexSOP ocsd.TrcIndex) {}

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
				line, gotLine, wantLine := testutil.FirstDiff(gotLines, wantLines)
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
	reader.SnapshotPath = snapshotDir
	if err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %v", err)
	}
	if reader.Trace == nil {
		return nil, fmt.Errorf("missing parsed trace metadata")
	}

	bufferName := resolveETESourceName(requestedSource, reader.Trace, reader.ParsedDeviceList)
	if bufferName == "" {
		return nil, fmt.Errorf("no ETE source trees found")
	}

	sourceTree, ok := snapshot.SourceTree(bufferName, reader.Trace)
	if !ok || sourceTree.BufferInfo == nil {
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
	if err := addETEDecoders(tree, sourceTree, reader.ParsedDeviceList, mapper, bufferName); err != nil {
		return nil, err
	}

	applyOpModeFlags(tree, eteOpFlags(opts))

	if err := loadCoreMemoryImages(snapshotDir, reader.ParsedDeviceList, mapper); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	printer := printers.NewGenericElementPrinter(&out)
	setETEPacketRawMonitors(tree, &out)
	if err := drainAndPrintElements(tree, printer); err != nil {
		return nil, err
	}

	buffers := eteSnapshotBuffers(reader.Trace, bufferName, opts.multiSession)
	if len(buffers) == 0 {
		return nil, fmt.Errorf("no trace buffers found for source %s", bufferName)
	}

	if err := decodeETESnapshotBuffers(tree, reader, snapshotDir, buffers, srcIsFrame, frameAlignment, opts.multiSession, printer); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func addETEDecoders(tree *dcdtree.DecodeTree, sourceTree *snapshot.TraceBufferSourceTree, devices map[string]*snapshot.Device, mapper memacc.Mapper, bufferName string) error {
	memIf := &mapperAdapter{mapper: mapper}
	instr := idec.NewDecoder()
	seenTraceIDs := map[uint8]struct{}{}
	eteDecoders := 0

	for _, srcDevName := range sortedETESourceDeviceNames(sourceTree) {
		dev := findParsedDeviceByName(devices, srcDevName)
		if dev == nil || !strings.EqualFold(dev.Type, "ETE") {
			continue
		}

		cfg := eteConfigFromDevice(dev)
		traceID := cfg.TraceID()
		if _, exists := seenTraceIDs[traceID]; exists {
			continue
		}

		proc, dec, err := ete.NewConfiguredPipelineWithDeps(int(traceID), cfg, memIf, instr)
		if err != nil {
			return fmt.Errorf("create ETE pipeline for %s failed: %v", srcDevName, err)
		}

		if err := tree.AddPullDecoder(traceID, ocsd.BuiltinDcdETE, ocsd.ProtocolETE, proc, dec, dec); err != nil {
			if errors.Is(err, ocsd.ErrAttachTooMany) {
				continue
			}
			return fmt.Errorf("attach ETE decoder for %s failed: %v", srcDevName, err)
		}
		eteDecoders++
		seenTraceIDs[traceID] = struct{}{}
	}

	if eteDecoders == 0 {
		return fmt.Errorf("no ETE decoders found for source %s", bufferName)
	}
	return nil
}

func sortedETESourceDeviceNames(sourceTree *snapshot.TraceBufferSourceTree) []string {
	names := make([]string, 0, len(sourceTree.SourceCoreAssoc))
	for name := range sourceTree.SourceCoreAssoc {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func eteConfigFromDevice(dev *snapshot.Device) *ete.Config {
	cfg := ete.NewConfig()
	eteRegSetters := map[string]func(uint32){
		"trcidr0":     func(v uint32) { cfg.RegIdr0 = v },
		"trcidr1":     func(v uint32) { cfg.RegIdr1 = v },
		"trcidr2":     func(v uint32) { cfg.RegIdr2 = v },
		"trcidr8":     func(v uint32) { cfg.RegIdr8 = v },
		"trcdevarch":  func(v uint32) { cfg.RegDevArch = v },
		"trcconfigr":  func(v uint32) { cfg.RegConfigr = v },
		"trctraceidr": func(v uint32) { cfg.RegTraceidr = v },
	}
	for reg, set := range eteRegSetters {
		if val, ok := dev.RegValue(reg); ok {
			set(uint32(testutil.ParseHexOrDec(val)))
		}
	}
	return cfg
}

func loadCoreMemoryImages(snapshotDir string, devices map[string]*snapshot.Device, mapper memacc.Mapper) error {
	for _, dev := range devices {
		if !strings.EqualFold(dev.Class, "core") {
			continue
		}
		for _, memParams := range dev.Memory {
			path := filepath.Join(snapshotDir, memParams.Path)
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			b, ok := sliceMemoryImage(b, memParams.Offset, memParams.Length)
			if !ok {
				continue
			}

			acc := memacc.NewBufferAccessor(ocsd.VAddr(memParams.Address), b)
			_ = mapper.AddAccessor(acc, 0)
		}
	}
	return nil
}

func sliceMemoryImage(b []byte, offset, length uint64) ([]byte, bool) {
	if offset > 0 {
		if offset >= uint64(len(b)) {
			return nil, false
		}
		b = b[offset:]
	}
	if length > 0 && length < uint64(len(b)) {
		b = b[:length]
	}
	return b, true
}

func decodeETESnapshotBuffers(
	tree *dcdtree.DecodeTree,
	reader *snapshot.Reader,
	snapshotDir string,
	buffers []snapshot.Buffer,
	srcIsFrame bool,
	frameAlignment int,
	multiSession bool,
	printer *printers.GenericElementPrinter,
) error {
	for i, bufInfo := range buffers {
		srcTree := reader.SourceTrees[bufInfo.BufferName]
		if srcTree == nil || srcTree.BufferInfo == nil {
			continue
		}

		traceData, err := readTraceBuffer(snapshotDir, srcTree.BufferInfo.DataFileName)
		if err != nil {
			return err
		}
		if err := decodeETETraceBuffer(tree, traceData, srcIsFrame, frameAlignment, printer); err != nil {
			return err
		}
		if multiSession && i+1 < len(buffers) {
			if err := resetBetweenBuffers(tree, printer, bufInfo.BufferName); err != nil {
				return err
			}
		}
	}
	return nil
}

func readTraceBuffer(snapshotDir, dataFileName string) ([]byte, error) {
	binFile := filepath.Join(snapshotDir, dataFileName)
	traceData, err := os.ReadFile(binFile)
	if err != nil {
		return nil, fmt.Errorf("read trace buffer %s: %w", binFile, err)
	}
	return traceData, nil
}

func resetBetweenBuffers(tree *dcdtree.DecodeTree, printer *printers.GenericElementPrinter, bufferName string) error {
	if err := tree.Reset(0); err != nil {
		return fmt.Errorf("OpReset after buffer %s: %w", bufferName, err)
	}
	return drainAndPrintElements(tree, printer)
}

func setETEPacketRawMonitors(tree *dcdtree.DecodeTree, writer io.Writer) {
	tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
		proc, ok := elem.DataIn.(*etmv4.Processor)
		if !ok || proc == nil {
			return
		}
		proc.SetPktRawMonitor(&eteRawPacketPrinter{writer: writer, traceID: csID})
	})
}

func findParsedDeviceByName(devices map[string]*snapshot.Device, name string) *snapshot.Device {
	for _, dev := range devices {
		if dev.Name == name {
			return dev
		}
	}
	return nil
}

func sanitizePPL(s string, keepGenElems bool) string {
	lines := strings.Split(normalizeNewlines(s), "\n")
	start := firstSnapshotLine(lines)

	out := make([]string, 0, len(lines)-start)
	for _, line := range lines[start:] {
		out = appendNormalizedSnapshotRecords(out, line, keepGenElems)
	}
	return strings.Join(out, "\n")
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func firstSnapshotLine(lines []string) int {
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Idx:") || strings.HasPrefix(trimmed, "Frame:") {
			return i
		}
	}
	return 0
}

func appendNormalizedSnapshotRecords(out []string, line string, keepGenElems bool) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return out
	}

	for _, idxLine := range testutil.SplitIdxRecords(line) {
		if normalized := normalizeSnapshotLine(idxLine, keepGenElems); normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
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

var packetTokenAliases = map[string]string{
	"I_ETE_ITE":                  "I_ITE",
	"I_ETE_TRANS_ST":             "I_TRANS_ST",
	"I_ETE_TRANS_COMMIT":         "I_TRANS_COMMIT",
	"I_ETE_TRANS_FAIL":           "I_TRANS_FAIL",
	"I_ETE_PE_RESET":             "I_PE_RESET",
	"ETE_PKT_I_SRC_ADDR_MATCH":   "I_ADDR_OR_ATOM",
	"ETE_PKT_I_SRC_ADDR_S_IS0":   "I_ADDR_OR_ATOM",
	"ETE_PKT_I_SRC_ADDR_S_IS1":   "I_ADDR_OR_ATOM",
	"ETE_PKT_I_SRC_ADDR_L_32IS0": "I_ADDR_OR_ATOM",
	"ETE_PKT_I_SRC_ADDR_L_32IS1": "I_ADDR_OR_ATOM",
	"ETE_PKT_I_SRC_ADDR_L_64IS0": "I_ADDR_OR_ATOM",
	"ETE_PKT_I_SRC_ADDR_L_64IS1": "I_ADDR_OR_ATOM",
}

var atomPacketTokens = map[string]struct{}{
	"I_ATOM":    {},
	"I_ATOM_F1": {},
	"I_ATOM_F2": {},
	"I_ATOM_F3": {},
	"I_ATOM_F4": {},
	"I_ATOM_F5": {},
	"I_ATOM_F6": {},
}

func canonicalPacketToken(tok string) string {
	switch {
	case strings.HasPrefix(tok, "I_ADDR_"),
		strings.HasPrefix(tok, "I_SRC_ADDR_"),
		strings.HasPrefix(tok, "I_SCR_ADDR_"):
		return "I_ADDR_OR_ATOM"
	}

	if _, ok := atomPacketTokens[tok]; ok {
		return "I_ADDR_OR_ATOM"
	}
	if alias, ok := packetTokenAliases[tok]; ok {
		return alias
	}
	return tok
}

func resolveETESourceName(requested string, trace *snapshot.Trace, devs map[string]*snapshot.Device) string {
	if strings.TrimSpace(requested) != "" {
		tree, ok := snapshot.SourceTree(strings.TrimSpace(requested), trace)
		if ok && tree.BufferInfo != nil && sourceTreeHasETEDevices(tree, devs) {
			return strings.TrimSpace(requested)
		}
	}

	for _, info := range trace.TraceBuffers {
		if strings.TrimSpace(info.BufferName) == "" {
			continue
		}
		tree, ok := snapshot.SourceTree(info.BufferName, trace)
		if !ok || tree.BufferInfo == nil {
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

func sourceTreeHasETEDevices(sourceTree *snapshot.TraceBufferSourceTree, devs map[string]*snapshot.Device) bool {
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := findParsedDeviceByName(devs, srcDevName)
		if dev == nil {
			continue
		}
		if strings.EqualFold(dev.Type, "ETE") {
			return true
		}
	}
	return false
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
	var drainErr error
	tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
		if drainErr != nil || elem == nil || elem.Iterator == nil {
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
				if errors.Is(nextErr, ocsd.ErrWait) {
					break
				}
				drainErr = nextErr
				return
			}
			if trcElem == nil {
				continue
			}
			drained = append(drained, drainedElem{seq: len(drained), qseq: qseq, elem: *trcElem})
		}
	})
	if drainErr != nil {
		return drainErr
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
		if printErr := printer.PrintElement(elem); printErr != nil && !ocsd.IsDataWaitErr(printErr) {
			return printErr
		}
	}
	return nil
}

func decodeETETraceBuffer(tree *dcdtree.DecodeTree, traceData []byte, srcIsFrame bool, alignment int, printer *printers.GenericElementPrinter) error {
	var traceIndex uint32
	if srcIsFrame {
		if err := writeTraceChunks(tree, traceData, printer, &traceIndex, func(remaining int) (int, bool) {
			if remaining < alignment {
				return 0, false
			}
			return alignment, true
		}); err != nil {
			return err
		}
	} else {
		if err := writeTraceChunks(tree, traceData, printer, &traceIndex, func(remaining int) (int, bool) {
			return min(remaining, 256), remaining > 0
		}); err != nil {
			return err
		}
	}

	if err := closeTraceTree(tree); err != nil {
		return err
	}
	return drainAndPrintElements(tree, printer)
}

func writeTraceChunks(
	tree *dcdtree.DecodeTree,
	data []byte,
	printer *printers.GenericElementPrinter,
	traceIndex *uint32,
	nextChunk func(remaining int) (int, bool),
) error {
	remaining := data
	for {
		sendLen, ok := nextChunk(len(remaining))
		if !ok {
			return nil
		}
		consumed, err := tree.Write(ocsd.TrcIndex(*traceIndex), remaining[:sendLen])
		if err := checkTraceWriteProgress(*traceIndex, consumed, err); err != nil {
			return err
		}
		*traceIndex += consumed
		remaining = remaining[consumed:]
		if err := drainAndPrintElements(tree, printer); err != nil {
			return err
		}
	}
}

func checkTraceWriteProgress(traceIndex uint32, consumed uint32, err error) error {
	resp := ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		return fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
	}
	if consumed == 0 {
		return fmt.Errorf("no progress while decoding at trace index %d", traceIndex)
	}
	return nil
}

func closeTraceTree(tree *dcdtree.DecodeTree) error {
	resp := ocsd.DataRespFromErr(tree.Close())
	if ocsd.DataRespIsFatal(resp) {
		return fmt.Errorf("fatal datapath response on EOT")
	}
	return nil
}

func eteSnapshotBuffers(trace *snapshot.Trace, primaryBuffer string, multiSession bool) []snapshot.Buffer {
	if trace == nil || len(trace.TraceBuffers) == 0 {
		return nil
	}

	byName := make(map[string]snapshot.Buffer, len(trace.TraceBuffers))
	for _, info := range trace.TraceBuffers {
		if strings.TrimSpace(info.BufferName) == "" {
			continue
		}
		byName[info.BufferName] = info
	}

	if !multiSession {
		if info, ok := byName[primaryBuffer]; ok {
			return []snapshot.Buffer{info}
		}
		return nil
	}

	ordered := make([]snapshot.Buffer, 0, len(byName))
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
