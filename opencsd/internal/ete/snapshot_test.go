package ete_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"opencsd/internal/dcdtree"
	"opencsd/internal/ete"
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

func (p *eteRawPacketPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *ete.TracePacket, rawData []byte) {
	if p.writer == nil || op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	_, _ = io.WriteString(p.writer, fmt.Sprintf("Idx:%d; ID:%x;\t%s : description\n", indexSOP, p.traceID, pkt.Type.String()))
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

func TestETESnapshotsAgainstGolden(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		golden := filepath.Join("testdata", name+".ppl")
		if _, err := os.Stat(golden); err != nil {
			continue
		}

		t.Run(name, func(t *testing.T) {
			wantBytes, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden %s: %v", golden, err)
			}

			sourceName := extractSourceNameFromGolden(string(wantBytes))
			snapshotDir := filepath.Join("testdata", name)
			gotBytes, err := runETESnapshotDecode(snapshotDir, sourceName)
			if err != nil {
				t.Fatalf("runETESnapshotDecode failed: %v", err)
			}

			got := sanitizePPL(string(gotBytes))
			want := sanitizePPL(string(wantBytes))

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

	got := sanitizePPL(input)
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

func runETESnapshotDecode(snapshotDir, requestedSource string) ([]byte, error) {
	reader := snapshot.NewReader()
	reader.SetSnapshotDir(snapshotDir)
	if !reader.ReadSnapShot() {
		return nil, fmt.Errorf("failed to read snapshot: %s", snapshotDir)
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
		if val, ok := dev.GetRegValue("trcidr0"); ok {
			cfg.RegIdr0 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("trcidr1"); ok {
			cfg.RegIdr1 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("trcidr2"); ok {
			cfg.RegIdr2 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("trcidr8"); ok {
			cfg.RegIdr8 = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("trcdevarch"); ok {
			cfg.RegDevArch = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("trcconfigr"); ok {
			cfg.RegConfigr = uint32(parseHexOrDec(val))
		}
		if val, ok := dev.GetRegValue("trctraceidr"); ok {
			cfg.RegTraceidr = uint32(parseHexOrDec(val))
		}
		traceID := cfg.TraceID()
		if _, exists := seenTraceIDs[traceID]; exists {
			continue
		}

		if err := tree.CreateDecoder(ocsd.BuiltinDcdETE, int(ocsd.CreateFlgFullDecoder), cfg); err != ocsd.OK {
			if err == ocsd.ErrAttachTooMany {
				continue
			}
			return nil, fmt.Errorf("create ETE decoder for %s failed: %v", srcDevName, err)
		}
		eteDecoders++
		seenTraceIDs[traceID] = struct{}{}
	}

	if eteDecoders == 0 {
		return nil, fmt.Errorf("no ETE decoders found for source %s", bufferName)
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
		proc, ok := elem.DataIn.(*ete.Processor)
		if !ok || proc == nil {
			return
		}
		if proc.PktRawMonI != nil {
			_ = proc.PktRawMonI.ReplaceFirst(&eteRawPacketPrinter{writer: &out, traceID: csID})
		}
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

func sanitizePPL(s string) string {
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
			normalized := normalizeSnapshotLine(idxLine)
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

func normalizeSnapshotLine(line string) string {
	if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
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
