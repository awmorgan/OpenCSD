package etmv3_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv3"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
	"opencsd/internal/testutil"
)

// mapperAdapter wraps memacc.Mapper to satisfy the tree's TargetMemAccess interface.
type mapperAdapter struct {
	mapper memacc.Mapper
}

func (m *mapperAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	buf := make([]byte, reqBytes)
	readBytes, err := m.mapper.Read(address, csTraceID, memSpace, reqBytes, buf)
	return readBytes, buf[:readBytes], err
}

func (m *mapperAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

// etmv3RawPacketPrinter implements common packet-monitor behavior for etmv3.Packet.
type etmv3RawPacketPrinter struct {
	writer  io.Writer
	traceID uint8
}

func (p *etmv3RawPacketPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if p.writer == nil || op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	etmPkt, ok := pkt.(*etmv3.Packet)
	if !ok {
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Idx:%d; ID:%x; [", indexSOP, p.traceID))
	for _, b := range rawData {
		sb.WriteString(fmt.Sprintf("0x%02x ", b))
	}
	sb.WriteString("];\t")
	sb.WriteString(etmv3PacketTypeName(etmPkt.Type))
	sb.WriteString(" : description")
	sb.WriteString("\n")
	_, _ = io.WriteString(p.writer, sb.String())
}

// etmv3PacketTypeName maps the Go ETMv3 PktType to the C++ packet type name exactly.
func etmv3PacketTypeName(t etmv3.PktType) string {
	switch t {
	case etmv3.PktNotSync:
		return "NOTSYNC"
	case etmv3.PktIncompleteEOT:
		return "INCOMPLETE_EOT."
	case etmv3.PktBranchAddress:
		return "BRANCH_ADDRESS"
	case etmv3.PktASync:
		return "A_SYNC"
	case etmv3.PktCycleCount:
		return "CYCLE_COUNT"
	case etmv3.PktISync:
		return "I_SYNC"
	case etmv3.PktISyncCycle:
		return "I_SYNC_CYCLE"
	case etmv3.PktTrigger:
		return "TRIGGER"
	case etmv3.PktPHdr:
		return "P_HDR"
	case etmv3.PktStoreFail:
		return "STORE_FAIL"
	case etmv3.PktOOOData:
		return "OOO_DATA"
	case etmv3.PktOOOAddrPlc:
		return "OOO_ADDR_PLC"
	case etmv3.PktNormData:
		return "NORM_DATA"
	case etmv3.PktDataSuppressed:
		return "DATA_SUPPRESSED"
	case etmv3.PktValNotTraced:
		return "VAL_NOT_TRACED"
	case etmv3.PktIgnore:
		return "IGNORE"
	case etmv3.PktContextID:
		return "CONTEXT_ID"
	case etmv3.PktVMID:
		return "VMID"
	case etmv3.PktExceptionEntry:
		return "EXCEPTION_ENTRY"
	case etmv3.PktExceptionExit:
		return "EXCEPTION_EXIT"
	case etmv3.PktTimestamp:
		return "TIMESTAMP"
	case etmv3.PktBadSequence:
		return "BAD_SEQUENCE"
	case etmv3.PktBadTraceMode:
		return "BAD_TRACEMODE"
	case etmv3.PktReserved:
		return "I_RESERVED"
	default:
		return "I_RESERVED"
	}
}

func TestETMv3SnapshotsAgainstGolden(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		sourceName string
		traceIDs   []string // hex trace IDs to filter for ETMv3
	}{
		{name: "TC2", sourceName: "ETB_0", traceIDs: []string{"10", "11", "12"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			snapshotDir := filepath.Join("testdata", tc.name)
			goldenPath := filepath.Join("testdata", tc.name+".ppl")

			goOut, err := runETMv3SnapshotDecode(snapshotDir, tc.sourceName)
			if err != nil {
				t.Fatalf("runETMv3SnapshotDecode failed: %v", err)
			}

			goldenBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden file %s: %v", goldenPath, err)
			}

			got := testutil.SanitizePPL(string(goOut), tc.traceIDs)
			want := testutil.SanitizePPL(string(goldenBytes), tc.traceIDs)

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

func runETMv3SnapshotDecode(snapshotDir, sourceName string) ([]byte, error) {
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

	// Set up memory and instruction decode dependencies.
	mapper := memacc.NewGlobalMapper()
	memIf := &mapperAdapter{mapper: mapper}
	instr := idec.NewDecoder()

	etmDecoders := 0
	for srcDevName := range sourceTree.SourceCoreAssoc {
		dev := testutil.FindParsedDeviceByName(reader.ParsedDeviceList, srcDevName)
		if dev == nil {
			continue
		}
		devType := strings.ToUpper(dev.DeviceTypeName)
		// Only create ETMv3 decoders - skip PTM, ETMv4, ITM, STM
		if !strings.HasPrefix(devType, "ETM") {
			continue
		}
		// Skip ETMv4 devices
		if strings.HasPrefix(devType, "ETM4") || strings.HasPrefix(devType, "ETMV4") {
			continue
		}

		cfg := &etmv3.Config{}
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
		proc, dec, err := etmv3.NewConfiguredPipelineWithDeps(int(traceID), cfg, nil, memIf, instr)
		if err != nil {
			return nil, fmt.Errorf("create ETMv3 pipeline for %s failed: %v", srcDevName, err)
		}

		if err := tree.AddWiredDecoder(traceID, ocsd.BuiltinDcdETMV3, ocsd.ProtocolETMV3, proc, dec, dec.SetTraceElemOut); err != nil {
			return nil, fmt.Errorf("attach ETMv3 decoder for %s failed: %v", srcDevName, err)
		}
		etmDecoders++
	}

	if etmDecoders == 0 {
		return nil, fmt.Errorf("no ETMv3 decoders found for source %s", sourceName)
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
	// Attach generic element printer.
	printer := printers.NewGenericElementPrinter(&out)
	tree.SetGenTraceElemOutI(printer)

	// Attach raw packet monitor to each ETMv3 decoder.
	tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
		proc, ok := elem.DataIn.(*etmv3.PktProc)
		if !ok || proc == nil {
			return
		}
		proc.SetPktRawMonitor(&etmv3RawPacketPrinter{writer: &out, traceID: csID})
	})

	// Read and feed trace data.
	binFile := filepath.Join(snapshotDir, sourceTree.BufferInfo.DataFileName)
	traceData, err := os.ReadFile(binFile)
	if err != nil {
		return nil, fmt.Errorf("read trace buffer %s: %w", binFile, err)
	}

	var traceIndex uint32
	if srcIsFrame {
		pending := traceData
		for len(pending) > 0 {
			sendLen := len(pending)
			if sendLen > 0 {
				sendLen -= sendLen % frameAlignment
			}
			if sendLen == 0 {
				break // remaining bytes less than one frame
			}
			consumed, err := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			resp := ocsd.DataRespFromErr(err)
			if ocsd.DataRespIsFatal(resp) {
				return nil, fmt.Errorf("fatal datapath response %d at trace index %d", resp, traceIndex)
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
				return nil, fmt.Errorf("fatal datapath response at trace index %d", traceIndex)
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
