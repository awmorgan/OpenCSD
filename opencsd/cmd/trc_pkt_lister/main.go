package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv3"
	"opencsd/internal/itm"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/ptm"
	"opencsd/internal/snapshot"
	"opencsd/internal/stm"
)

const defaultLogFile = "trc_pkt_lister.ppl"

type options struct {
	ssDir            string
	ssVerbose        bool
	srcName          string
	multiSession     bool
	decode           bool
	decodeOnly       bool
	pktMon           bool
	stats            bool
	profile          bool
	noTimePrint      bool
	outRawPacked     bool
	outRawUnpacked   bool
	dstreamFormat    bool
	tpiuFormat       bool
	hasHSync         bool
	testWaits        int
	allSourceIDs     bool
	idList           []uint8
	additionalFlags  uint32
	memCacheDisable  bool
	memCachePageSize uint32
	memCachePageNum  uint32
	logStdout        bool
	logStderr        bool
	logFile          bool
	logFileName      string
	help             bool
}

type packetPrinter interface {
	SetMute(bool)
}

type memAccAdapter struct {
	mapper memacc.Mapper
}

func (m *memAccAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	buf := make([]byte, reqBytes)
	readBytes := reqBytes
	err := m.mapper.ReadTargetMemory(address, csTraceID, memSpace, &readBytes, buf)
	return readBytes, buf[:readBytes], err
}

func (m *memAccAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

type mappedRange struct {
	start ocsd.VAddr
	end   ocsd.VAddr
	space ocsd.MemSpaceAcc
	path  string
}

type filteredGenElemPrinter struct {
	printer      *printers.GenericElementPrinter
	allSourceIDs bool
	ids          map[uint8]struct{}
}

func (g *filteredGenElemPrinter) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if !g.allSourceIDs {
		if _, ok := g.ids[trcChanID]; !ok {
			return ocsd.RespCont
		}
	}
	return g.printer.TraceElemIn(indexSOP, trcChanID, elem)
}

type ptmRawPrinter struct {
	writer io.Writer
	id     uint8
}

func (p *ptmRawPrinter) SetMute(bool) {}

func (p *ptmRawPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *ptm.Packet, rawData []byte) {
	if op == ocsd.OpEOT {
		fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
		return
	}
	if op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	fmt.Fprintf(p.writer, "Idx:%d; ID:%x; [", indexSOP, p.id)
	for _, b := range rawData {
		fmt.Fprintf(p.writer, "0x%02x ", b)
	}
	fmt.Fprintf(p.writer, "];\t%s\n", pkt.String())
}

type etmv3RawPrinter struct {
	writer io.Writer
	id     uint8
}

func (p *etmv3RawPrinter) SetMute(bool) {}

func (p *etmv3RawPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *etmv3.Packet, rawData []byte) {
	if op == ocsd.OpEOT {
		fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
		return
	}
	if op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	fmt.Fprintf(p.writer, "Idx:%d; ID:%x; [", indexSOP, p.id)
	for _, b := range rawData {
		fmt.Fprintf(p.writer, "0x%02x ", b)
	}
	fmt.Fprintf(p.writer, "];\t%s\n", pkt.String())
}

type itmRawPrinter struct {
	writer io.Writer
	id     uint8
}

func (p *itmRawPrinter) SetMute(bool) {}

func (p *itmRawPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *itm.Packet, rawData []byte) {
	if op == ocsd.OpEOT {
		fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
		return
	}
	if op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	fmt.Fprintf(p.writer, "Idx:%d; ID:%x; [", indexSOP, p.id)
	for _, b := range rawData {
		fmt.Fprintf(p.writer, "0x%02x ", b)
	}
	fmt.Fprintf(p.writer, "];\t%s\n", pkt.String())
}

type stmRawPrinter struct {
	writer io.Writer
	id     uint8
}

func (p *stmRawPrinter) SetMute(bool) {}

func (p *stmRawPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *stm.Packet, rawData []byte) {
	if op == ocsd.OpEOT {
		fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
		return
	}
	if op != ocsd.OpData || pkt == nil || len(rawData) == 0 {
		return
	}
	fmt.Fprintf(p.writer, "Idx:%d; ID:%x; [", indexSOP, p.id)
	for _, b := range rawData {
		fmt.Fprintf(p.writer, "0x%02x ", b)
	}
	fmt.Fprintf(p.writer, "];\t%s\n", pkt.String())
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	if opts.help {
		printHelp(os.Stdout)
		return nil
	}
	if opts.ssDir == "" {
		return errors.New("Trace Packet Lister : Error: Missing directory string on -ss_dir option")
	}

	out, closeFn, err := configureOutput(opts)
	if err != nil {
		return err
	}
	defer closeFn()

	logHeader(out)
	logCmdLine(out, append([]string{os.Args[0]}, args...))

	fmt.Fprintf(out, "Trace Packet Lister : reading snapshot from path %s\n", opts.ssDir)

	reader := snapshot.NewReader()
	reader.SetSnapshotDir(opts.ssDir)
	reader.Verbose = opts.ssVerbose
	if !reader.ReadSnapShot() {
		return errors.New("Trace Packet Lister : Failed to read snapshot")
	}

	sourceNames := getSourceNames(reader)
	if len(sourceNames) == 0 {
		return errors.New("Trace Packet Lister : No trace source buffer names found")
	}

	if opts.srcName == "" {
		opts.srcName = sourceNames[0]
	} else {
		valid := false
		for _, src := range sourceNames {
			if src == opts.srcName {
				valid = true
				break
			}
		}
		if !valid {
			fmt.Fprintf(out, "Trace Packet Lister : Trace source name %s not found\n", opts.srcName)
			fmt.Fprintln(out, "Valid source names are:-")
			for _, src := range sourceNames {
				fmt.Fprintln(out, src)
			}
			return nil
		}
	}

	fmt.Fprintf(out, "Using %s as trace source\n", opts.srcName)
	return listTracePackets(out, reader, opts, sourceNames)
}

func listTracePackets(out io.Writer, reader *snapshot.Reader, opts options, sourceNames []string) error {
	builder := snapshot.NewCreateDcdTreeFromSnapShot(reader)
	packetProcOnly := !opts.decode
	if !builder.CreateDecodeTree(opts.srcName, packetProcOnly) {
		return fmt.Errorf("Trace Packet Lister : Failed to create decode tree for source %s", opts.srcName)
	}

	tree := builder.GetDecodeTree()
	if tree == nil {
		return errors.New("Trace Packet Lister : No supported protocols found.")
	}

	configureFrameDemux(tree, out, opts)

	mapper := memacc.NewGlobalMapper()
	tree.SetMemAccessI(&memAccAdapter{mapper: mapper})
	mapped := mapMemoryRanges(mapper, opts.ssDir, reader)

	genPrinter := printers.NewGenericElementPrinter(out)
	genAdapter := &filteredGenElemPrinter{
		printer:      genPrinter,
		allSourceIDs: opts.allSourceIDs,
		ids:          makeIDSet(opts.idList),
	}

	printersAttached := 0
	if !opts.decodeOnly {
		printersAttached = attachPacketPrinters(out, tree, opts)
	}

	if opts.decode {
		tree.SetGenTraceElemOutI(genAdapter)
		fmt.Fprintln(out, "Trace Packet Lister : Set trace element decode printer")
		if opts.profile {
			genPrinter.SetMute(true)
			genPrinter.SetCollectStats()
		}
		printMappedRanges(out, mapped)
	}

	if !opts.decode && printersAttached == 0 {
		fmt.Fprintln(out, "Trace Packet Lister : No supported protocols found.")
		return nil
	}

	if !opts.multiSession {
		return processInputFile(out, tree, builder.GetBufferFileName(), genPrinter, opts)
	}

	total := len(sourceNames)
	for i, sourceName := range sourceNames {
		fmt.Fprintf(out, "####### Multi Session decode: Buffer %d of %d; Source name = %s.\n\n", i+1, total, sourceName)
		srcTree, ok := reader.SourceTrees[sourceName]
		if !ok || srcTree == nil || srcTree.BufferInfo == nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s - buffer not found. Aborting.\n\n", sourceName)
			break
		}
		binFile := filepath.Join(reader.SnapshotPath, srcTree.BufferInfo.DataFileName)
		if err := processInputFile(out, tree, binFile, genPrinter, opts); err != nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s failed. Aborting.\n\n", sourceName)
			return err
		}
		fmt.Fprintf(out, "####### Buffer %d : %s Complete\n\n", i+1, sourceName)
	}
	return nil
}

func processInputFile(out io.Writer, tree *dcdtree.DecodeTree, fileName string, genPrinter *printers.GenericElementPrinter, opts options) error {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintln(out, "Trace Packet Lister : Error : Unable to open trace buffer.")
		return err
	}
	defer file.Close()

	start := time.Now()
	var traceIndex uint32
	dataPathResp := ocsd.RespCont
	buf := make([]byte, 1024)
	pending := make([]byte, 0, 2048)
	align := frameAlignment(tree)
	isFramed := tree.GetFrameDeformatter() != nil

	pushPending := func() {
		for len(pending) > 0 && !ocsd.DataRespIsFatal(dataPathResp) {
			sendLen := len(pending)
			if isFramed {
				sendLen -= sendLen % align
				if sendLen == 0 {
					break
				}
			}
			used, resp := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			dataPathResp = resp
			if used > 0 {
				pending = pending[used:]
				traceIndex += used
			}
			if ocsd.DataRespIsWait(dataPathResp) {
				if genPrinter.NeedAckWait() {
					genPrinter.AckWait()
				}
				_, dataPathResp = tree.TraceDataIn(ocsd.OpFlush, 0, nil)
				continue
			}
			if used == 0 {
				break
			}
			if !isFramed {
				continue
			}
		}
	}

	for dataPathResp < ocsd.RespFatalNotInit {
		n := 0
		if opts.dstreamFormat {
			n, err = io.ReadFull(file, buf[:512-8])
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				n = max(n, 0)
			} else if err != nil {
				break
			}
		} else {
			n, err = file.Read(buf)
			if err == io.EOF {
				if n == 0 {
					break
				}
			} else if err != nil {
				break
			}
		}

		if n > 0 {
			pending = append(pending, buf[:n]...)
			pushPending()
		}

		if opts.dstreamFormat {
			footer := make([]byte, 8)
			_, ferr := io.ReadFull(file, footer)
			if ferr == nil && opts.outRawPacked {
				fmt.Fprint(out, "DSTREAM footer [")
				for _, b := range footer {
					fmt.Fprintf(out, "0x%x ", b)
				}
				fmt.Fprintln(out, "]")
			}
			if ferr == io.EOF || ferr == io.ErrUnexpectedEOF {
				break
			}
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	if !ocsd.DataRespIsFatal(dataPathResp) && len(pending) > 0 && !isFramed {
		pushPending()
	}

	if ocsd.DataRespIsFatal(dataPathResp) {
		fmt.Fprintln(out, "Trace Packet Lister : Data Path fatal error")
		if opts.ssVerbose {
			fmt.Fprintf(os.Stderr, "[trc_pkt_lister] fatal response=%d at trace index=%d pending=%d\n", dataPathResp, traceIndex, len(pending))
		}
		return errors.New("fatal datapath error")
	}

	tree.TraceDataIn(ocsd.OpEOT, 0, nil)

	if opts.multiSession {
		tree.TraceDataIn(ocsd.OpReset, 0, nil)
	}

	fmt.Fprintf(out, "Trace Packet Lister : Trace buffer done, processed %d bytes", traceIndex)
	if opts.noTimePrint {
		fmt.Fprintln(out, ".")
	} else {
		fmt.Fprintf(out, " in %.8f seconds.\n", time.Since(start).Seconds())
	}

	if opts.stats {
		fmt.Fprint(out, "\nReading packet decoder statistics....\n\n")
		fmt.Fprintln(out, "Decode stats unavailable in Go port for this snapshot.")
	}

	if opts.profile {
		genPrinter.PrintStats()
	}

	return nil
}

func frameAlignment(tree *dcdtree.DecodeTree) int {
	deformatter := tree.GetFrameDeformatter()
	if deformatter == nil {
		return 1
	}
	flags := deformatter.GetConfigFlags()
	if (flags & ocsd.DfrmtrHasHsyncs) != 0 {
		return 2
	}
	if (flags & ocsd.DfrmtrHasFsyncs) != 0 {
		return 4
	}
	return 16
}

func attachPacketPrinters(out io.Writer, tree *dcdtree.DecodeTree, opts options) int {
	attached := 0
	idFilter := makeIDSet(opts.idList)
	type elemRef struct {
		id   uint8
		elem *dcdtree.DecodeTreeElement
	}
	elems := make([]elemRef, 0)
	tree.ForEachElement(func(csID uint8, elem *dcdtree.DecodeTreeElement) {
		elems = append(elems, elemRef{id: csID, elem: elem})
	})
	sort.Slice(elems, func(i, j int) bool { return elems[i].id < elems[j].id })

	for _, ref := range elems {
		csID := ref.id
		elem := ref.elem
		if !opts.allSourceIDs {
			if _, ok := idFilter[csID]; !ok {
				continue
			}
		}

		protocolName := elem.DecoderTypeName
		ok := false

		switch proc := elem.DataIn.(type) {
		case *ptm.PktProc:
			_ = proc.PktRawMonI.ReplaceFirst(&ptmRawPrinter{writer: out, id: csID})
			ok = true
		case *etmv3.PktProc:
			_ = proc.PktRawMonI.ReplaceFirst(&etmv3RawPrinter{writer: out, id: csID})
			ok = true
		case *itm.PktProc:
			_ = proc.PktRawMonI.ReplaceFirst(&itmRawPrinter{writer: out, id: csID})
			ok = true
		case *stm.PktProc:
			_ = proc.PktRawMonI.ReplaceFirst(&stmRawPrinter{writer: out, id: csID})
			ok = true
		}

		if ok {
			fmt.Fprintf(out, "Trace Packet Lister : Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
			attached++
		} else {
			fmt.Fprintf(out, "Trace Packet Lister : Failed to Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
		}
	}
	return attached
}

func configureFrameDemux(tree *dcdtree.DecodeTree, out io.Writer, opts options) {
	deformatter := tree.GetFrameDeformatter()
	if deformatter == nil {
		return
	}

	flags := deformatter.GetConfigFlags()
	if opts.tpiuFormat {
		flags |= ocsd.DfrmtrHasFsyncs
	}
	if opts.hasHSync {
		flags |= ocsd.DfrmtrHasHsyncs
	}
	if opts.tpiuFormat {
		flags &^= ocsd.DfrmtrFrameMemAlign
	}
	if flags == 0 {
		flags = ocsd.DfrmtrFrameMemAlign
	}

	if opts.outRawPacked {
		flags |= ocsd.DfrmtrPackedRawOut
	}
	if opts.outRawUnpacked {
		flags |= ocsd.DfrmtrUnpackedRawOut
	}

	_ = deformatter.Configure(flags)
	if opts.outRawPacked || opts.outRawUnpacked {
		rp := printers.NewRawFramePrinter(out)
		deformatter.SetRawTraceFrame(rp)
	}
}

func mapMemoryRanges(mapper memacc.Mapper, ssDir string, reader *snapshot.Reader) []mappedRange {
	ranges := make([]mappedRange, 0)
	for _, dev := range reader.ParsedDeviceList {
		if !strings.EqualFold(dev.DeviceClass, "core") {
			continue
		}
		for _, memParams := range dev.DumpDefs {
			filePath := filepath.Join(ssDir, memParams.Path)
			b, err := os.ReadFile(filePath)
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
			if len(b) == 0 {
				continue
			}

			acc := memacc.NewBufferAccessor(ocsd.VAddr(memParams.Address), b)
			space := parseMemSpace(memParams.Space)
			acc.SetMemSpace(space)
			if mapper.AddAccessor(acc, 0) != ocsd.OK {
				continue
			}

			ranges = append(ranges, mappedRange{
				start: ocsd.VAddr(memParams.Address),
				end:   ocsd.VAddr(memParams.Address + uint64(len(b)) - 1),
				space: space,
				path:  filepath.ToSlash(filePath),
			})
		}
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})
	return ranges
}

func printMappedRanges(out io.Writer, ranges []mappedRange) {
	fmt.Fprintln(out, "Gen_Info : Mapped Memory Accessors")
	for _, r := range ranges {
		fmt.Fprintf(out, "Gen_Info : FileAcc; Range::0x%x:0x%x; Mem Space::%s\n", uint64(r.start), uint64(r.end), memacc.GetMemSpaceString(r.space))
		fmt.Fprintf(out, "Filename=%s\n", r.path)
	}
	fmt.Fprintln(out, "Gen_Info : ========================")
}

func configureOutput(opts options) (io.Writer, func(), error) {
	outputs := make([]io.Writer, 0, 3)
	closers := make([]io.Closer, 0, 1)

	if opts.logStdout {
		outputs = append(outputs, os.Stdout)
	}
	if opts.logStderr {
		outputs = append(outputs, os.Stderr)
	}
	if opts.logFile {
		f, err := os.Create(opts.logFileName)
		if err != nil {
			return nil, nil, fmt.Errorf("Trace Packet Lister : Error: cannot open logfile %s: %w", opts.logFileName, err)
		}
		outputs = append(outputs, f)
		closers = append(closers, f)
	}

	if len(outputs) == 0 {
		outputs = append(outputs, os.Stdout)
	}

	closeFn := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}

	if len(outputs) == 1 {
		return outputs[0], closeFn, nil
	}
	return io.MultiWriter(outputs...), closeFn, nil
}

func parseOptions(args []string) (options, error) {
	opts := options{
		allSourceIDs: true,
		logStdout:    true,
		logFile:      true,
		logFileName:  defaultLogFile,
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-ss_dir":
			i++
			if i >= len(args) {
				return opts, errors.New("Trace Packet Lister : Error: Missing directory string on -ss_dir option")
			}
			opts.ssDir = args[i]
		case "-ss_verbose":
			opts.ssVerbose = true
		case "-id":
			i++
			if i >= len(args) {
				return opts, errors.New("Trace Packet Lister : Error: No ID number on -id option")
			}
			v, err := strconv.ParseUint(args[i], 0, 8)
			if err != nil {
				return opts, fmt.Errorf("Trace Packet Lister : Error: invalid ID number %s on -id option", args[i])
			}
			id := uint8(v)
			if !ocsd.IsValidCSSrcID(id) {
				return opts, fmt.Errorf("Trace Packet Lister : Error: invalid ID number 0x%x on -id option", id)
			}
			opts.allSourceIDs = false
			opts.idList = append(opts.idList, id)
		case "-src_name":
			i++
			if i >= len(args) {
				return opts, errors.New("Trace Packet Lister : Error: Missing source name string on -src_name option")
			}
			opts.srcName = args[i]
			opts.multiSession = false
		case "-multi_session":
			if opts.srcName == "" {
				opts.multiSession = true
			}
		case "-decode":
			opts.decode = true
		case "-decode_only":
			opts.decodeOnly = true
			opts.decode = true
		case "-pkt_mon":
			opts.pktMon = true
		case "-stats":
			opts.stats = true
		case "-profile":
			opts.profile = true
		case "-no_time_print":
			opts.noTimePrint = true
		case "-o_raw_packed":
			opts.outRawPacked = true
		case "-o_raw_unpacked":
			opts.outRawUnpacked = true
		case "-dstream_format":
			opts.dstreamFormat = true
		case "-tpiu":
			opts.tpiuFormat = true
		case "-tpiu_hsync":
			opts.tpiuFormat = true
			opts.hasHSync = true
		case "-direct_br_cond":
			opts.additionalFlags |= ocsd.OpflgNUncondDirBrChk
		case "-strict_br_cond":
			opts.additionalFlags |= ocsd.OpflgStrictNUncondBrChk
		case "-range_cont":
			opts.additionalFlags |= ocsd.OpflgChkRangeContinue
		case "-halt_err":
			opts.additionalFlags |= ocsd.OpflgPktdecHaltBadPkts
		case "-aa64_opcode_chk", "-src_addr_n":
			// Accepted for compatibility; no-op for currently ported protocol set.
		case "-test_waits":
			i++
			if i >= len(args) {
				return opts, errors.New("Trace Packet Lister : Error: wait count value on -test_waits option")
			}
			v, _ := strconv.Atoi(args[i])
			if v < 0 {
				v = 0
			}
			opts.testWaits = v
		case "-macc_cache_disable":
			opts.memCacheDisable = true
		case "-macc_cache_p_size":
			i++
			if i < len(args) {
				v, _ := strconv.ParseUint(args[i], 0, 32)
				opts.memCachePageSize = uint32(v)
			}
		case "-macc_cache_p_num":
			i++
			if i < len(args) {
				v, _ := strconv.ParseUint(args[i], 0, 32)
				opts.memCachePageNum = uint32(v)
			}
		case "-logstdout":
			opts.logStdout = true
			opts.logStderr = false
			opts.logFile = false
		case "-logstderr":
			opts.logStdout = false
			opts.logStderr = true
			opts.logFile = false
		case "-logfile":
			opts.logStdout = false
			opts.logStderr = false
			opts.logFile = true
		case "-logfilename":
			i++
			if i >= len(args) {
				return opts, errors.New("Trace Packet Lister : Error: Missing file name string on -logfilename option")
			}
			opts.logFileName = args[i]
			opts.logStdout = false
			opts.logStderr = false
			opts.logFile = true
		case "-help", "--help", "-h":
			opts.help = true
		default:
			fmt.Fprintf(os.Stderr, "Trace Packet Lister : Warning: Ignored unknown option %s.\n", a)
		}
	}

	return opts, nil
}

func logHeader(out io.Writer) {
	fmt.Fprintln(out, "Trace Packet Lister: CS Decode library testing")
	fmt.Fprintln(out, "-----------------------------------------------")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "** Library Version : 1.8.0")
	fmt.Fprintln(out)
}

func logCmdLine(out io.Writer, args []string) {
	fmt.Fprintln(out, "Test Command Line:-")
	for i, a := range args {
		if i == 0 {
			fmt.Fprintf(out, "%s   ", a)
			continue
		}
		fmt.Fprintf(out, "%s  ", a)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)
}

func printHelp(out io.Writer) {
	fmt.Fprintln(out, "Trace Packet Lister - commands")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Snapshot:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-ss_dir <dir>       Set the directory path to a trace snapshot")
	fmt.Fprintln(out, "-ss_verbose         Verbose output when reading the snapshot")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Decode:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-id <n>             Set an ID to list (may be used multiple times)")
	fmt.Fprintln(out, "-src_name <name>    List packets from a given snapshot source name")
	fmt.Fprintln(out, "-multi_session      Decode all source buffers with same config")
	fmt.Fprintln(out, "-dstream_format     Input is DSTREAM framed")
	fmt.Fprintln(out, "-tpiu               Input from TPIU - sync by FSYNC")
	fmt.Fprintln(out, "-tpiu_hsync         Input from TPIU - sync by FSYNC and HSYNC")
	fmt.Fprintln(out, "-decode             Full decode of packets from snapshot")
	fmt.Fprintln(out, "-decode_only        Decode only, no packet printer output")
	fmt.Fprintln(out, "-o_raw_packed       Output raw packed trace frames")
	fmt.Fprintln(out, "-o_raw_unpacked     Output raw unpacked trace data per ID")
	fmt.Fprintln(out, "-stats              Output packet processing statistics")
	fmt.Fprintln(out, "-no_time_print      Do not output elapsed time")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Output:")
	fmt.Fprintln(out, "-logstdout          Output to stdout")
	fmt.Fprintln(out, "-logstderr          Output to stderr")
	fmt.Fprintln(out, "-logfile            Output to default file")
	fmt.Fprintln(out, "-logfilename <name> Output to file <name>")
}

func getSourceNames(reader *snapshot.Reader) []string {
	if reader.ParsedTrace == nil {
		return nil
	}
	result := make([]string, 0, len(reader.ParsedTrace.TraceBuffers))
	for _, b := range reader.ParsedTrace.TraceBuffers {
		result = append(result, b.BufferName)
	}
	return result
}

func makeIDSet(ids []uint8) map[uint8]struct{} {
	set := make(map[uint8]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func parseMemSpace(space string) ocsd.MemSpaceAcc {
	s := strings.TrimSpace(strings.ToLower(space))
	switch s {
	case "s", "secure":
		return ocsd.MemSpaceS
	case "n", "nonsecure", "ns":
		return ocsd.MemSpaceN
	case "r", "realm":
		return ocsd.MemSpaceR
	case "el1s":
		return ocsd.MemSpaceEL1S
	case "el1n":
		return ocsd.MemSpaceEL1N
	case "el2":
		return ocsd.MemSpaceEL2
	case "el3":
		return ocsd.MemSpaceEL3
	case "root":
		return ocsd.MemSpaceRoot
	default:
		return ocsd.MemSpaceAny
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
