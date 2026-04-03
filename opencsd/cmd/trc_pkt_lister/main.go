package main

import (
	"bufio"
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
	"sync"
	"time"

	"opencsd/internal/common"
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

	// parse-only flag state used to finalize composite options.
	flagDecodeOnly   bool
	flagTPIU         bool
	flagTPIUHSync    bool
	flagDirectBrCond bool
	flagStrictBrCond bool
	flagRangeCont    bool
	flagHaltErr      bool
	flagSrcAddrN     bool
	flagAA64Opcode   bool
	flagLogStdout    bool
	flagLogStderr    bool
	flagLogFile      bool
	flagLogFileName  string
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

func (g *filteredGenElemPrinter) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	if !g.allSourceIDs {
		if !g.validIDs[trcChanID] {
			return nil
		}
	}
	return g.printer.TraceElemIn(indexSOP, trcChanID, elem)
}

type genericRawPrinter struct {
	writer io.Writer
	id     uint8
}

type synchronizedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *synchronizedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

func (p *genericRawPrinter) SetMute(bool) {}

func (p *genericRawPrinter) RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if op == ocsd.OpEOT {
		fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
		return
	}

	if op != ocsd.OpData || len(rawData) == 0 {
		return
	}

	formattedPkt := pkt.String()
	if formattedPkt == "" {
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
		return errors.New("trace packet lister: error: missing directory string on -ss_dir option")
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
		return fmt.Errorf("trace packet lister: failed to read snapshot: %w", err)
	}

	sourceNames := getSourceNames(reader)
	if len(sourceNames) == 0 {
		return errors.New("trace packet lister: no trace source buffer names found")
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
			return fmt.Errorf("trace packet lister: trace source name %q not found", opts.srcName)
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
	streamOut := &synchronizedWriter{w: out}

	builder := snapshot.NewDecodeTreeBuilder(reader)
	packetProcOnly := !opts.decode
	tree, err := builder.Build(opts.srcName, packetProcOnly)
	if err != nil {
		return fmt.Errorf("trace packet lister: failed to create decode tree for source %s: %w", opts.srcName, err)
	}

	if tree == nil {
		return errors.New("trace packet lister: no supported protocols found")
	}

	if err := configureFrameDemux(tree, streamOut, opts); err != nil {
		return err
	}
	if err := applyAdditionalFlags(tree, opts.additionalFlags); err != nil {
		return err
	}

	mapped := []mappedRange{}
	if opts.decode {
		mapper := builder.MemoryMapper()
		if mapper == nil {
			return errors.New("trace packet lister: decode mode requires a memory mapper")
		}

		if opts.memCacheDisable {
			if err := mapper.EnableCaching(false); err != nil {
				return fmt.Errorf("trace packet lister: configure memory cache disable=true failed: %w", err)
			}
		} else {
			if err := mapper.EnableCaching(true); err != nil {
				return fmt.Errorf("trace packet lister: configure memory cache disable=false failed: %w", err)
			}
			if opts.memCachePageSize != 0 || opts.memCachePageNum != 0 {
				pageSize := opts.memCachePageSize
				if pageSize == 0 {
					pageSize = memacc.DefaultPageSize
				}
				numPages := opts.memCachePageNum
				if numPages == 0 {
					numPages = uint32(memacc.DefaultNumPages)
				}
				if err := mapper.SetCacheSizes(uint16(pageSize), int(numPages), false); err != nil {
					return fmt.Errorf("trace packet lister: configure memory cache sizes page_size=%d page_num=%d failed: %w", pageSize, numPages, err)
				}
			}
		}

		var err error
		mapped, err = mapMemoryRanges(mapper, opts.ssDir, reader)
		if err != nil {
			return err
		}
	}

	genPrinter := printers.NewGenericElementPrinter(streamOut)
	genAdapter := &filteredGenElemPrinter{
		printer:      genPrinter,
		allSourceIDs: opts.allSourceIDs,
		validIDs:     makeIDSet(opts.idList),
	}

	printersAttached := 0
	if !opts.decodeOnly {
		printersAttached = attachPacketPrinters(streamOut, tree, opts)
	}

	if opts.decode {
		fmt.Fprintln(out, "Trace Packet Lister : Set trace element decode printer")
		if opts.testWaits > 0 {
			genPrinter.SetTestWaits(opts.testWaits)
		}
		if opts.profile {
			genPrinter.SetMute(true)
			genPrinter.SetCollectStats()
		}
		printMappedRanges(streamOut, mapped)
	}

	if !opts.decode && printersAttached == 0 {
		fmt.Fprintln(out, "Trace Packet Lister : No supported protocols found.")
		return nil
	}

	if !opts.multiSession {
		var pullAdapter *common.PushToPullAdapter
		if opts.decode {
			pullAdapter = common.NewPushToPullAdapter()
			tree.SetGenTraceElemOutI(pullAdapter)
		}
		return processInputFile(streamOut, tree, builder.BufferFileName(), pullAdapter, genAdapter, genPrinter, opts)
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
		var pullAdapter *common.PushToPullAdapter
		if opts.decode {
			pullAdapter = common.NewPushToPullAdapter()
			tree.SetGenTraceElemOutI(pullAdapter)
		}
		if err := processInputFile(streamOut, tree, binFile, pullAdapter, genAdapter, genPrinter, opts); err != nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s failed. Aborting.\n\n", sourceName)
			return err
		}
		fmt.Fprintf(out, "####### Buffer %d : %s Complete\n\n", i+1, sourceName)
	}
	return nil
}

func fatalDataPathError(resp ocsd.DatapathResp, traceIndex uint32, pendingLen int) error {
	return fmt.Errorf(
		"trace packet lister: data path fatal response=%d trace_index=%d pending=%d",
		resp, traceIndex, pendingLen,
	)
}

func framedTailError(traceIndex uint32, pendingLen, align int) error {
	return fmt.Errorf(
		"trace packet lister: leftover framed tail bytes at EOF: trace_index=%d pending=%d align=%d",
		traceIndex, pendingLen, align,
	)
}

func processInputFile(out io.Writer, tree *dcdtree.DecodeTree, fileName string, adapter *common.PushToPullAdapter, genAdapter *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options) error {
	if adapter == nil || genAdapter == nil {
		return processInputFileProducer(out, tree, fileName, genPrinter, opts)
	}

	if err := drainBootstrapElements(adapter, genAdapter, genPrinter); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		err := processInputFileProducer(out, tree, fileName, genPrinter, opts)
		adapter.CloseWithError(err)
		errCh <- err
	}()

	for {
		elem, err := adapter.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			adapter.CloseWithError(err)
			<-errCh
			return err
		}

		ackNeeded := true
		err = genAdapter.TraceElemIn(elem.Index, elem.TraceID, elem)
		if ocsd.IsDataContErr(err) {
			adapter.Ack()
			ackNeeded = false
			continue
		}
		if ocsd.IsDataWaitErr(err) {
			if genPrinter.NeedAckWait() {
				genPrinter.AckWait()
			}
			adapter.Ack()
			ackNeeded = false
			continue
		}
		if err != nil {
			if ackNeeded {
				adapter.Ack()
			}
			adapter.CloseWithError(err)
			<-errCh
			return fmt.Errorf("trace packet lister: generic element processing error: %w", err)
		}
		if ackNeeded {
			adapter.Ack()
		}
	}

	if err := <-errCh; err != nil {
		return err
	}
	return nil
}

func drainBootstrapElements(adapter *common.PushToPullAdapter, genAdapter *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter) error {
	if adapter == nil || genAdapter == nil {
		return nil
	}

	for {
		elem, err := adapter.TryNext()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		ackNeeded := true
		err = genAdapter.TraceElemIn(elem.Index, elem.TraceID, elem)
		if ocsd.IsDataContErr(err) {
			adapter.Ack()
			ackNeeded = false
			continue
		}
		if ocsd.IsDataWaitErr(err) {
			if genPrinter.NeedAckWait() {
				genPrinter.AckWait()
			}
			adapter.Ack()
			ackNeeded = false
			continue
		}
		if err != nil {
			if ackNeeded {
				adapter.Ack()
			}
			return fmt.Errorf("trace packet lister: generic element bootstrap processing error: %w", err)
		}
		if ackNeeded {
			adapter.Ack()
		}
	}
}

func processInputFileProducer(out io.Writer, tree *dcdtree.DecodeTree, fileName string, genPrinter *printers.GenericElementPrinter, opts options) error {
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("trace packet lister: error: unable to open trace buffer %s: %w", fileName, err)
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
	var footer [8]byte

	pushPending := func() {
		for len(pending) > 0 && !ocsd.DataRespIsFatal(dataPathResp) {
			sendLen := len(pending)
			if isFramed {
				sendLen -= sendLen % align
				if sendLen == 0 {
					break
				}
			}

			used, dpErr := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), pending[:sendLen])
			dataPathResp = ocsd.DataRespFromErr(dpErr)
			if dpErr != nil {
				dataPathErr = dpErr
				if !ocsd.DataRespIsFatal(dataPathResp) {
					return
				}
			}

			if used > 0 {
				n := copy(pending, pending[used:])
				pending = pending[:n]
				traceIndex += used
			}

			if ocsd.DataRespIsFatal(dataPathResp) {
				return
			}

			if ocsd.DataRespIsWait(dataPathResp) {
				var dpErr error
				_, dpErr = tree.TraceDataIn(ocsd.OpFlush, 0, nil)
				dataPathResp = ocsd.DataRespFromErr(dpErr)
				if dpErr != nil {
					dataPathErr = fmt.Errorf("flush after wait: %w", dpErr)
					return
				}
				if ocsd.DataRespIsFatal(dataPathResp) {
					return
				}
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
			if dataPathErr != nil || ocsd.DataRespIsFatal(dataPathResp) {
				break
			}
		}

		if opts.dstreamFormat {
			_, ferr := io.ReadFull(file, footer[:])
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
			if ferr != nil {
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
		return fatalDataPathError(dataPathResp, traceIndex, len(pending))
	}

	if dataPathErr != nil {
		return fmt.Errorf("trace packet lister: data path processing error: %w", dataPathErr)
	}

	if isFramed && len(pending) > 0 {
		return framedTailError(traceIndex, len(pending), align)
	}

	if _, err := tree.TraceDataIn(ocsd.OpEOT, 0, nil); err != nil {
		return fmt.Errorf("trace packet lister: OpEOT error: %w", err)
	}

	if opts.multiSession {
		if _, err := tree.TraceDataIn(ocsd.OpReset, 0, nil); err != nil {
			return fmt.Errorf("trace packet lister: OpReset error: %w", err)
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

func applyAdditionalFlags(tree *dcdtree.DecodeTree, flags uint32) error {
	if tree == nil || flags == 0 {
		return nil
	}

	apply := func(component any) error {
		applier, ok := component.(common.FlagApplier)
		if !ok || applier == nil {
			return nil
		}
		if err := applier.ApplyFlags(flags); err != nil {
			return fmt.Errorf("apply flags for %T with flags 0x%x: %w", component, flags, err)
		}
		return nil
	}
	var applyErr error

	tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
		if elem == nil || applyErr != nil {
			return
		}
		if err := apply(elem.FlagApplier); err != nil {
			applyErr = err
		}
	})

	return applyErr
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
			proc.SetPktRawMonitor(&genericRawPrinter{
				writer: out,
				id:     csID,
			})
			ok = true
		case *etmv3.PktProc:
			proc.SetPktRawMonitor(&genericRawPrinter{
				writer: out,
				id:     csID,
			})
			ok = true
		case *etmv4.Processor:
			proc.SetPktRawMonitor(&genericRawPrinter{
				writer: out,
				id:     csID,
			})
			ok = true
		case *itm.PktProc:
			proc.SetPktRawMonitor(&genericRawPrinter{
				writer: out,
				id:     csID,
			})
			ok = true
		case *stm.PktProc:
			proc.SetPktRawMonitor(&genericRawPrinter{
				writer: out,
				id:     csID,
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
func configureFrameDemux(tree *dcdtree.DecodeTree, out io.Writer, opts options) error {
	deformatter := tree.FrameDeformatter()
	if deformatter == nil {
		return nil
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

	if err := deformatter.Configure(flags); err != nil {
		return fmt.Errorf("configure frame deformatter flags=0x%x: %w", flags, err)
	}
	if opts.outRawPacked || opts.outRawUnpacked {
		rp := printers.NewRawFramePrinter(out)
		deformatter.SetRawTraceFrame(rp)
	}
	return nil
}

func mapMemoryRanges(mapper memacc.Mapper, ssDir string, reader *snapshot.Reader) ([]mappedRange, error) {
	ranges := make([]mappedRange, 0)
	seenAccessors := make(map[string]struct{})
	loadErrs := make([]string, 0)

	recordLoadErr := func(filePath string, memParams snapshot.DumpDef, format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		loadErrs = append(loadErrs, fmt.Sprintf(
			"path=%s address=0x%x offset=%d length=%d space=%q: %s",
			filepath.ToSlash(filePath),
			memParams.Address,
			memParams.Offset,
			memParams.Length,
			memParams.Space,
			msg,
		))
	}

	for _, dev := range reader.ParsedDeviceList {
		if dev == nil || !strings.EqualFold(dev.DeviceClass, "core") {
			continue
		}
		for _, memParams := range dev.DumpDefs {
			if strings.TrimSpace(memParams.Path) == "" {
				continue
			}

			filePath := filepath.Join(ssDir, memParams.Path)
			normPath := filepath.ToSlash(filePath)
			space := parseMemSpace(memParams.Space)

			f, err := os.Open(filePath)
			if err != nil {
				// Missing/unreadable external dump images are non-fatal: match snapshot builder behavior.
				continue
			}

			stat, err := f.Stat()
			if err != nil {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "stat failed: %v", err)
				continue
			}
			fileSize := stat.Size()

			if memParams.Offset >= uint64(fileSize) {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "offset beyond EOF: file_size=%d requested_offset=%d", fileSize, memParams.Offset)
				continue
			}

			var windowLen uint64
			if memParams.Length == 0 {
				windowLen = uint64(fileSize) - memParams.Offset
			} else {
				remaining := uint64(fileSize) - memParams.Offset
				windowLen = min(memParams.Length, remaining)
			}

			if windowLen == 0 {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "effective mapping length is zero")
				continue
			}

			accKey := fmt.Sprintf(
				"%s|%s|0x%x|%d|%d",
				memacc.MemSpaceString(space),
				normPath,
				memParams.Address,
				windowLen,
				memParams.Offset,
			)
			if _, seen := seenAccessors[accKey]; seen {
				_ = f.Close()
				continue
			}

			b := make([]byte, windowLen)
			if _, err := f.ReadAt(b, int64(memParams.Offset)); err != nil && err != io.EOF {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "read failed: %v", err)
				continue
			}

			if err := f.Close(); err != nil {
				recordLoadErr(filePath, memParams, "close failed: %v", err)
				continue
			}

			acc := memacc.NewBufferAccessor(ocsd.VAddr(memParams.Address), b)
			acc.SetMemSpace(space)
			if err := mapper.AddAccessor(acc, ocsd.BadCSSrcID); err != nil {
				if !errors.Is(err, ocsd.ErrMemAccOverlap) {
					return nil, fmt.Errorf("add memory accessor for %s @0x%x: %w", filePath, memParams.Address, err)
				}
			}
			seenAccessors[accKey] = struct{}{}

			ranges = append(ranges, mappedRange{
				start: ocsd.VAddr(memParams.Address),
				end:   ocsd.VAddr(memParams.Address + windowLen - 1),
				space: space,
				path:  normPath,
			})
		}
	}

	if len(loadErrs) > 0 {
		return nil, fmt.Errorf("trace packet lister: snapshot memory mapping load failures:\n%s", strings.Join(loadErrs, "\n"))
	}

	return ranges, nil
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
	flushers := make([]*bufio.Writer, 0, 3)
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
			return nil, nil, fmt.Errorf("trace packet lister: error: cannot open logfile %s: %w", opts.logFileName, err)
		}
		outputs = append(outputs, f)
		closers = append(closers, f)
	}

	if len(outputs) == 0 {
		outputs = append(outputs, os.Stdout)
	}

	bufferedOutputs := make([]io.Writer, 0, len(outputs))
	for _, out := range outputs {
		bw := bufio.NewWriter(out)
		flushers = append(flushers, bw)
		bufferedOutputs = append(bufferedOutputs, bw)
	}

	closeFn := func() {
		for _, f := range flushers {
			_ = f.Flush()
		}
		for _, c := range closers {
			_ = c.Close()
		}
	}

	if len(bufferedOutputs) == 1 {
		return bufferedOutputs[0], closeFn, nil
	}
	return io.MultiWriter(bufferedOutputs...), closeFn, nil
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

type uint32Value struct {
	target *uint32
}

func (u *uint32Value) String() string {
	if u == nil || u.target == nil {
		return "0"
	}
	return strconv.FormatUint(uint64(*u.target), 10)
}

func (u *uint32Value) Set(value string) error {
	v, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return err
	}
	*u.target = uint32(v)
	return nil
}

func (o *options) finalizeParsedFlags() {
	if o.flagDecodeOnly {
		o.decodeOnly = true
		o.decode = true
	}

	if o.flagTPIU {
		o.tpiuFormat = true
	}
	if o.flagTPIUHSync {
		o.tpiuFormat = true
		o.hasHSync = true
	}

	if o.flagDirectBrCond {
		o.additionalFlags |= ocsd.OpflgNUncondDirBrChk
	}
	if o.flagStrictBrCond {
		o.additionalFlags |= ocsd.OpflgStrictNUncondBrChk
	}
	if o.flagRangeCont {
		o.additionalFlags |= ocsd.OpflgChkRangeContinue
	}
	if o.flagHaltErr {
		o.additionalFlags |= ocsd.OpflgPktdecHaltBadPkts
	}
	if o.flagSrcAddrN {
		o.additionalFlags |= ocsd.OpflgPktdecSrcAddrNAtoms
	}
	if o.flagAA64Opcode {
		o.additionalFlags |= ocsd.OpflgPktdecAA64OpcodeChk
	}

	if len(o.idList) > 0 {
		o.allSourceIDs = false
	}

	switch {
	case o.flagLogStdout:
		o.logStdout = true
		o.logStderr = false
		o.logFile = false
	case o.flagLogStderr:
		o.logStdout = false
		o.logStderr = true
		o.logFile = false
	case o.flagLogFileName != "":
		o.logFileName = o.flagLogFileName
		o.logStdout = false
		o.logStderr = false
		o.logFile = true
	case o.flagLogFile:
		o.logStdout = false
		o.logStderr = false
		o.logFile = true
	}
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
	fs.Var((*idListValue)(&opts.idList), "id", "Set an ID to list (may be used multiple times)")

	fs.BoolVar(&opts.flagDecodeOnly, "decode_only", false, "Decode only, no packet printer output")
	fs.BoolVar(&opts.flagTPIU, "tpiu", false, "Input from TPIU - sync by FSYNC")
	fs.BoolVar(&opts.flagTPIUHSync, "tpiu_hsync", false, "Input from TPIU - sync by FSYNC and HSYNC")

	fs.BoolVar(&opts.flagDirectBrCond, "direct_br_cond", false, "Additional flag: direct_br_cond")
	fs.BoolVar(&opts.flagStrictBrCond, "strict_br_cond", false, "Additional flag: strict_br_cond")
	fs.BoolVar(&opts.flagRangeCont, "range_cont", false, "Additional flag: range_cont")
	fs.BoolVar(&opts.flagHaltErr, "halt_err", false, "Additional flag: halt_err")
	fs.BoolVar(&opts.flagSrcAddrN, "src_addr_n", false, "Additional flag: src_addr_n")
	fs.BoolVar(&opts.flagAA64Opcode, "aa64_opcode_chk", false, "Additional flag: aa64_opcode_chk")

	fs.Var(&uint32Value{target: &opts.memCachePageSize}, "macc_cache_p_size", "Memory cache page size")
	fs.Var(&uint32Value{target: &opts.memCachePageNum}, "macc_cache_p_num", "Memory cache page number")

	fs.BoolVar(&opts.flagLogStdout, "logstdout", false, "Output to stdout")
	fs.BoolVar(&opts.flagLogStderr, "logstderr", false, "Output to stderr")
	fs.BoolVar(&opts.flagLogFile, "logfile", false, "Output to default file")
	fs.StringVar(&opts.flagLogFileName, "logfilename", "", "Output to specific file name")

	fs.BoolVar(&opts.help, "help", false, "Show help")

	// Parse the arguments
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			opts.help = true
			return opts, nil
		}
		return opts, fmt.Errorf("trace packet lister: error parsing flags: %w", err)
	}

	if opts.help {
		opts.help = true
		return opts, nil
	}

	opts.finalizeParsedFlags()

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
