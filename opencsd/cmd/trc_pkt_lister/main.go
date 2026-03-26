package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv3"
	"opencsd/internal/etmv4"
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

type opModeComponent interface {
	SetComponentOpMode(opFlags uint32) error
	ComponentOpMode() uint32
	SupportedOpModes() uint32
}

type memAccAdapter struct {
	mapper memacc.Mapper
}

func (m *memAccAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	buf := make([]byte, reqBytes)
	readBytes, err := m.mapper.Read(address, csTraceID, memSpace, reqBytes, buf)
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
	validIDs     [256]bool
}

func (g *filteredGenElemPrinter) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if !g.allSourceIDs {
		if !g.validIDs[trcChanID] {
			return ocsd.RespCont
		}
	}
	return g.printer.TraceElemIn(indexSOP, trcChanID, elem)
}

type genericRawPrinter[T any] struct {
	writer   io.Writer
	id       uint8
	formatFn func(T) string
}

func (p *genericRawPrinter[T]) SetMute(bool) {}

func (p *genericRawPrinter[T]) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt T, rawData []byte) {
	if op == ocsd.OpEOT {
		fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
		return
	}

	formattedPkt := p.formatFn(pkt)
	if op != ocsd.OpData || formattedPkt == "" || len(rawData) == 0 {
		return
	}

	fmt.Fprintf(p.writer, "Idx:%d; ID:%x; [", indexSOP, p.id)
	for _, b := range rawData {
		fmt.Fprintf(p.writer, "0x%02x ", b)
	}
	fmt.Fprintf(p.writer, "];\t%s\n", formattedPkt)
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
	reader.SetDir(opts.ssDir)
	reader.Verbose = opts.ssVerbose
	if err := reader.Read(); err != nil {
		return fmt.Errorf("Trace Packet Lister : Failed to read snapshot: %w", err)
	}

	sourceNames := getSourceNames(reader)
	if len(sourceNames) == 0 {
		return errors.New("Trace Packet Lister : No trace source buffer names found")
	}

	if opts.srcName == "" {
		opts.srcName = sourceNames[0]
	} else {
		valid := slices.Contains(sourceNames, opts.srcName)
		if !valid {
			fmt.Fprintf(out, "Trace Packet Lister : Trace source name %s not found\n", opts.srcName)
			fmt.Fprintln(out, "Valid source names are:-")
			for _, src := range sourceNames {
				fmt.Fprintln(out, src)
			}
			return nil
		}
	}

	if opts.multiSession && opts.srcName != "" {
		sourceNames = rotateSourceNames(sourceNames, opts.srcName)
	}

	fmt.Fprintf(out, "Using %s as trace source\n", opts.srcName)
	return listTracePackets(out, reader, opts, sourceNames)
}

func rotateSourceNames(sourceNames []string, first string) []string {
	idx := slices.Index(sourceNames, first)
	if idx <= 0 {
		return sourceNames
	}
	rotated := make([]string, 0, len(sourceNames))
	rotated = append(rotated, sourceNames[idx:]...)
	rotated = append(rotated, sourceNames[:idx]...)
	return rotated
}

func listTracePackets(out io.Writer, reader *snapshot.Reader, opts options, sourceNames []string) error {
	builder := snapshot.NewDecodeTreeBuilder(reader)
	packetProcOnly := !opts.decode
	tree, err := builder.Build(opts.srcName, packetProcOnly)
	if err != nil {
		return fmt.Errorf("Trace Packet Lister : Failed to create decode tree for source %s: %w", opts.srcName, err)
	}

	if tree == nil {
		return errors.New("Trace Packet Lister : No supported protocols found.")
	}

	configureFrameDemux(tree, out, opts)
	applyAdditionalFlags(tree, opts.additionalFlags)

	mapper := memacc.NewGlobalMapper()
	if opts.memCacheDisable {
		_ = mapper.EnableCaching(false)
	} else {
		_ = mapper.EnableCaching(true)
		if opts.memCachePageSize != 0 || opts.memCachePageNum != 0 {
			pageSize := opts.memCachePageSize
			if pageSize == 0 {
				pageSize = memacc.DefaultPageSize
			}
			numPages := opts.memCachePageNum
			if numPages == 0 {
				numPages = uint32(memacc.DefaultNumPages)
			}
			_ = mapper.SetCacheSizes(uint16(pageSize), int(numPages), false)
		}
	}
	tree.SetMemAccessI(&memAccAdapter{mapper: mapper})
	mapped := mapMemoryRanges(mapper, opts.ssDir, reader)

	genPrinter := printers.NewGenericElementPrinter(out)
	genAdapter := &filteredGenElemPrinter{
		printer:      genPrinter,
		allSourceIDs: opts.allSourceIDs,
		validIDs:     makeIDSet(opts.idList),
	}

	printersAttached := 0
	if !opts.decodeOnly {
		printersAttached = attachPacketPrinters(out, tree, opts)
	}

	if opts.decode {
		tree.SetGenTraceElemOutI(genAdapter)
		fmt.Fprintln(out, "Trace Packet Lister : Set trace element decode printer")
		if opts.testWaits > 0 {
			genPrinter.SetTestWaits(opts.testWaits)
		}
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
		return processInputFile(out, tree, builder.BufferFileName(), genPrinter, opts)
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
		return fmt.Errorf("Trace Packet Lister : Error : Unable to open trace buffer %s: %w", fileName, err)
	}
	defer file.Close()

	start := time.Now()
	var traceIndex uint32
	dataPathResp := ocsd.RespCont
	var dataPathErr error

	buf := make([]byte, 1024)
	pending := make([]byte, 0, 2048)
	align := frameAlignment(tree)
	isFramed := tree.FrameDeformatter() != nil

	pushPending := func() {
		for len(pending) > 0 && !ocsd.DataRespIsFatal(dataPathResp) {
			sendLen := len(pending)
			if isFramed {
				sendLen -= sendLen % align
				if sendLen == 0 {
					break
				}
			}

			used, resp, dpErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			dataPathResp = resp
			if dpErr != nil {
				dataPathErr = dpErr
				return
			}

			if used > 0 {
				n := copy(pending, pending[used:])
				pending = pending[:n]
				traceIndex += used
			}

			if ocsd.DataRespIsWait(dataPathResp) {
				if genPrinter.NeedAckWait() {
					genPrinter.AckWait()
				}
				_, dataPathResp, _ = tree.TraceDataIn(ocsd.OpFlush, 0, nil)
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
		var n int
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

	if dataPathErr != nil {
		return fmt.Errorf("Trace Packet Lister : Data path processing error: %w", dataPathErr)
	}

	if ocsd.DataRespIsFatal(dataPathResp) {
		fmt.Fprintln(out, "Trace Packet Lister : Data Path fatal error")
		if opts.ssVerbose {
			fmt.Fprintf(os.Stderr, "[trc_pkt_lister] fatal response=%d at trace index=%d pending=%d\n", dataPathResp, traceIndex, len(pending))
		}
	} else {
		if _, _, err := tree.TraceDataIn(ocsd.OpEOT, 0, nil); err != nil {
			return fmt.Errorf("Trace Packet Lister : OpEOT error: %w", err)
		}

		if opts.multiSession {
			if _, _, err := tree.TraceDataIn(ocsd.OpReset, 0, nil); err != nil {
				return fmt.Errorf("Trace Packet Lister : OpReset error: %w", err)
			}
		}
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
	deformatter := tree.FrameDeformatter()
	if deformatter == nil {
		return 1
	}
	flags := deformatter.ConfigFlags()
	if (flags & ocsd.DfrmtrHasHsyncs) != 0 {
		return 2
	}
	if (flags & ocsd.DfrmtrHasFsyncs) != 0 {
		return 4
	}
	return 16
}

func applyAdditionalFlags(tree *dcdtree.DecodeTree, flags uint32) {
	if tree == nil || flags == 0 {
		return
	}

	apply := func(component any) {
		opComp, ok := component.(opModeComponent)
		if !ok || opComp == nil {
			return
		}
		supported := opComp.SupportedOpModes()
		applyFlags := flags & supported
		if applyFlags == 0 {
			return
		}
		_ = opComp.SetComponentOpMode(opComp.ComponentOpMode() | applyFlags)
	}

	tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
		if elem == nil {
			return
		}
		apply(elem.DecoderHandle)
		if elem.DataIn != elem.DecoderHandle {
			apply(elem.DataIn)
		}
	})
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
			if !idFilter[csID] {
				continue
			}
		}

		protocolName := elem.DecoderTypeName
		ok := false

		switch proc := elem.DataIn.(type) {
		case *ptm.PktProc:
			proc.SetPktRawMonitor(&genericRawPrinter[*ptm.Packet]{
				writer: out, id: csID,
				formatFn: func(pkt *ptm.Packet) string {
					if pkt == nil {
						return ""
					}
					return pkt.String()
				},
			})
			ok = true
		case *etmv3.PktProc:
			proc.SetPktRawMonitor(&genericRawPrinter[*etmv3.Packet]{
				writer: out, id: csID,
				formatFn: func(pkt *etmv3.Packet) string {
					if pkt == nil {
						return ""
					}
					return pkt.String()
				},
			})
			ok = true
		case *etmv4.Processor:
			proc.SetPktRawMonitor(&genericRawPrinter[*etmv4.TracePacket]{
				writer: out, id: csID,
				formatFn: func(pkt *etmv4.TracePacket) string {
					if pkt == nil {
						return ""
					}
					return pkt.HeaderString() // Unique string formatter
				},
			})
			ok = true
		case *itm.PktProc:
			proc.SetPktRawMonitor(&genericRawPrinter[*itm.Packet]{
				writer: out, id: csID,
				formatFn: func(pkt *itm.Packet) string {
					if pkt == nil {
						return ""
					}
					return pkt.String()
				},
			})
			ok = true
		case *stm.PktProc:
			proc.SetPktRawMonitor(&genericRawPrinter[*stm.Packet]{
				writer: out, id: csID,
				formatFn: func(pkt *stm.Packet) string {
					if pkt == nil {
						return ""
					}
					return pkt.String()
				},
			})
			ok = true
		}

		if ok {
			fmt.Fprintf(out, "Trace Packet Lister : Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
			attached++
		} else {
			fmt.Fprintf(out, "Trace Packet Lister : Failed to attach Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
		}
	}
	return attached
}
func configureFrameDemux(tree *dcdtree.DecodeTree, out io.Writer, opts options) {
	deformatter := tree.FrameDeformatter()
	if deformatter == nil {
		return
	}

	flags := deformatter.ConfigFlags()
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
	seenFiles := make(map[string]struct{})
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
			if err := mapper.AddAccessor(acc, 0); err != nil {
				continue
			}

			normPath := filepath.ToSlash(filePath)
			if _, seen := seenFiles[normPath]; seen {
				continue
			}
			seenFiles[normPath] = struct{}{}

			ranges = append(ranges, mappedRange{
				start: ocsd.VAddr(memParams.Address),
				end:   ocsd.VAddr(memParams.Address + uint64(len(b)) - 1),
				space: space,
				path:  normPath,
			})
		}
	}

	return ranges
}

func printMappedRanges(out io.Writer, ranges []mappedRange) {
	fmt.Fprintln(out, "Gen_Info : Mapped Memory Accessors")
	for _, r := range ranges {
		fmt.Fprintf(out, "Gen_Info : FileAcc; Range::0x%x:%x; Mem Space::%s\n", uint64(r.start), uint64(r.end), memacc.MemSpaceString(r.space))
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

// idListValue implements flag.Value to allow multiple -id flags to be parsed into a slice.
type idListValue []uint8

func (i *idListValue) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *idListValue) Set(value string) error {
	v, err := strconv.ParseUint(value, 0, 8)
	if err != nil {
		return fmt.Errorf("invalid ID number %s", value)
	}
	id := uint8(v)
	if !ocsd.IsValidCSSrcID(id) {
		return fmt.Errorf("invalid ID number 0x%x", id)
	}
	*i = append(*i, id)
	return nil
}

func parseOptions(args []string) (options, error) {
	opts := options{
		allSourceIDs: true,
		logStdout:    true,
		logFile:      true,
		logFileName:  defaultLogFile,
	}

	fs := flag.NewFlagSet("Trace Packet Lister", flag.ContinueOnError)

	// Override default usage to rely on existing printHelp function
	fs.Usage = func() {}

	// Standard flags mapped directly to the options struct
	fs.StringVar(&opts.ssDir, "ss_dir", "", "Set the directory path to a trace snapshot")
	fs.BoolVar(&opts.ssVerbose, "ss_verbose", false, "Verbose output when reading the snapshot")
	fs.StringVar(&opts.srcName, "src_name", "", "List packets from a given snapshot source name")
	fs.BoolVar(&opts.multiSession, "multi_session", false, "Decode all source buffers with same config")
	fs.BoolVar(&opts.decode, "decode", false, "Full decode of packets from snapshot")
	fs.BoolVar(&opts.pktMon, "pkt_mon", false, "Enable packet monitor")
	fs.BoolVar(&opts.stats, "stats", false, "Output packet processing statistics")
	fs.BoolVar(&opts.profile, "profile", false, "Profile output")
	fs.BoolVar(&opts.noTimePrint, "no_time_print", false, "Do not output elapsed time")
	fs.BoolVar(&opts.outRawPacked, "o_raw_packed", false, "Output raw packed trace frames")
	fs.BoolVar(&opts.outRawUnpacked, "o_raw_unpacked", false, "Output raw unpacked trace data per ID")
	fs.BoolVar(&opts.dstreamFormat, "dstream_format", false, "Input is DSTREAM framed")
	fs.IntVar(&opts.testWaits, "test_waits", 0, "Wait count value")
	fs.BoolVar(&opts.memCacheDisable, "macc_cache_disable", false, "Disable memory cache")

	// Custom flag for multiple IDs
	var ids idListValue
	fs.Var(&ids, "id", "Set an ID to list (may be used multiple times)")

	// Intermediate variables for composite/complex logic
	var decodeOnly, tpiu, tpiuHsync bool
	fs.BoolVar(&decodeOnly, "decode_only", false, "Decode only, no packet printer output")
	fs.BoolVar(&tpiu, "tpiu", false, "Input from TPIU - sync by FSYNC")
	fs.BoolVar(&tpiuHsync, "tpiu_hsync", false, "Input from TPIU - sync by FSYNC and HSYNC")

	// Bitfield flags mapping
	var directBrCond, strictBrCond, rangeCont, haltErr, srcAddrN, aa64OpcodeChk bool
	fs.BoolVar(&directBrCond, "direct_br_cond", false, "Additional flag: direct_br_cond")
	fs.BoolVar(&strictBrCond, "strict_br_cond", false, "Additional flag: strict_br_cond")
	fs.BoolVar(&rangeCont, "range_cont", false, "Additional flag: range_cont")
	fs.BoolVar(&haltErr, "halt_err", false, "Additional flag: halt_err")
	fs.BoolVar(&srcAddrN, "src_addr_n", false, "Additional flag: src_addr_n")
	fs.BoolVar(&aa64OpcodeChk, "aa64_opcode_chk", false, "Additional flag: aa64_opcode_chk")

	// Cache pagination mapped to uint instead of uint32 for the flag parser
	var memCachePageSize, memCachePageNum uint
	fs.UintVar(&memCachePageSize, "macc_cache_p_size", 0, "Memory cache page size")
	fs.UintVar(&memCachePageNum, "macc_cache_p_num", 0, "Memory cache page number")

	// Output routing flags
	var logStdout, logStderr, logFile bool
	var logFileName string
	fs.BoolVar(&logStdout, "logstdout", false, "Output to stdout")
	fs.BoolVar(&logStderr, "logstderr", false, "Output to stderr")
	fs.BoolVar(&logFile, "logfile", false, "Output to default file")
	fs.StringVar(&logFileName, "logfilename", "", "Output to specific file name")

	// Help flags
	var help bool
	fs.BoolVar(&help, "help", false, "Show help")

	// Parse the arguments
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			opts.help = true
			return opts, nil
		}
		return opts, fmt.Errorf("Trace Packet Lister : Error parsing flags: %w", err)
	}

	if help {
		opts.help = true
		return opts, nil
	}

	if decodeOnly {
		opts.decodeOnly = true
		opts.decode = true
	}

	if tpiu {
		opts.tpiuFormat = true
	}
	if tpiuHsync {
		opts.tpiuFormat = true
		opts.hasHSync = true
	}

	// Apply bitfield combinations
	if directBrCond {
		opts.additionalFlags |= ocsd.OpflgNUncondDirBrChk
	}
	if strictBrCond {
		opts.additionalFlags |= ocsd.OpflgStrictNUncondBrChk
	}
	if rangeCont {
		opts.additionalFlags |= ocsd.OpflgChkRangeContinue
	}
	if haltErr {
		opts.additionalFlags |= ocsd.OpflgPktdecHaltBadPkts
	}
	if srcAddrN {
		opts.additionalFlags |= ocsd.OpflgPktdecSrcAddrNAtoms
	}
	if aa64OpcodeChk {
		opts.additionalFlags |= ocsd.OpflgPktdecAA64OpcodeChk
	}

	// Apply ID list
	if len(ids) > 0 {
		opts.allSourceIDs = false
		opts.idList = append(opts.idList, ids...)
	}

	// Cast cache numbers back to uint32
	if memCachePageSize > 0 {
		opts.memCachePageSize = uint32(memCachePageSize)
	}
	if memCachePageNum > 0 {
		opts.memCachePageNum = uint32(memCachePageNum)
	}

	// Apply mutual-exclusive logging rules
	if logStdout {
		opts.logStdout = true
		opts.logStderr = false
		opts.logFile = false
	} else if logStderr {
		opts.logStdout = false
		opts.logStderr = true
		opts.logFile = false
	} else if logFileName != "" {
		opts.logFileName = logFileName
		opts.logStdout = false
		opts.logStderr = false
		opts.logFile = true
	} else if logFile {
		opts.logStdout = false
		opts.logStderr = false
		opts.logFile = true
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

func makeIDSet(ids []uint8) [256]bool {
	var validIDs [256]bool
	for _, id := range ids {
		validIDs[id] = true
	}
	return validIDs
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
