package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"opencsd/internal/common"
	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv3"
	"opencsd/internal/etmv4"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/ptm"
	"opencsd/internal/snapshot"
	"opencsd/internal/stm"
)

// flag parsing types and helpers moved to config.go

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

func (g *filteredGenElemPrinter) PrintElement(elem *ocsd.TraceElement) error {
	if elem == nil {
		return nil
	}
	if !g.allSourceIDs {
		if !g.validIDs[elem.TraceID] {
			return nil
		}
	}
	return g.printer.PrintElement(elem)
}

type genericRawPrinter struct {
	writer       io.Writer
	id           uint8
	showRawBytes bool
}

type synchronizedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

type countingReader struct {
	r io.Reader
	n uint32
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += uint32(n)
	return n, err
}

func (r *countingReader) Count() uint32 {
	return r.n
}

func (w *synchronizedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

func (p *genericRawPrinter) SetMute(bool) {}

func (p *genericRawPrinter) MonitorRawData(indexSOP ocsd.TrcIndex, pkt fmt.Stringer, rawData []byte) {
	if len(rawData) == 0 {
		return
	}

	formattedPkt := pkt.String()
	if formattedPkt == "" {
		return
	}

	if p.showRawBytes {
		fmt.Fprintf(p.writer, "Idx:%d; ID:%x; [", indexSOP, p.id)
		for _, b := range rawData {
			fmt.Fprintf(p.writer, "0x%02x ", b)
		}
		fmt.Fprintf(p.writer, "];\t%s\n", formattedPkt)
	} else {
		fmt.Fprintf(p.writer, "Idx:%d; ID:%x;\t%s\n", indexSOP, p.id, formattedPkt)
	}
}

func (p *genericRawPrinter) MonitorEOT() {
	fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
}

func (p *genericRawPrinter) MonitorReset(indexSOP ocsd.TrcIndex) {}

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
	p, err := buildDecodePipeline(out, reader, opts)
	if err != nil {
		return err
	}

	if _, err := configureDecodeMode(p.streamOut, p.builder, reader, p.genPrinter, opts); err != nil {
		return err
	}

	if !opts.decode && p.printersAttached == 0 {
		fmt.Fprintln(out, "Trace Packet Lister : No supported protocols found.")
		return nil
	}

	if !opts.multiSession {
		return runSingleSession(
			p.streamOut,
			p.tree,
			p.builder.BufferFileName(),
			p.genAdapter,
			p.genPrinter,
			opts,
		)
	}

	return runMultiSession(
		p.streamOut,
		reader,
		p.tree,
		sourceNames,
		p.genAdapter,
		p.genPrinter,
		opts,
	)
}

type decodePipeline struct {
	streamOut        *synchronizedWriter
	builder          *snapshot.DecodeTreeBuilder
	tree             *dcdtree.DecodeTree
	genPrinter       *printers.GenericElementPrinter
	genAdapter       *filteredGenElemPrinter
	printersAttached int
}

func buildDecodePipeline(
	out io.Writer,
	reader *snapshot.Reader,
	opts options,
) (*decodePipeline, error) {
	streamOut := &synchronizedWriter{w: out}

	builder := snapshot.NewDecodeTreeBuilder(reader)
	packetProcOnly := !opts.decode
	tree, err := builder.Build(opts.srcName, packetProcOnly)
	if err != nil {
		return nil, fmt.Errorf(
			"trace packet lister: failed to create decode tree for source %s: %w",
			opts.srcName, err,
		)
	}
	if tree == nil {
		return nil, errors.New("trace packet lister: no supported protocols found")
	}

	if err := configureFrameDemux(tree, streamOut, opts); err != nil {
		return nil, err
	}
	if err := applyAdditionalFlags(tree, opts.additionalFlags); err != nil {
		return nil, err
	}

	output := configurePacketOutput(streamOut, tree, opts)

	return &decodePipeline{
		streamOut:        streamOut,
		builder:          builder,
		tree:             tree,
		genPrinter:       output.genPrinter,
		genAdapter:       output.genAdapter,
		printersAttached: output.printersAttached,
	}, nil
}

type packetOutput struct {
	genPrinter       *printers.GenericElementPrinter
	genAdapter       *filteredGenElemPrinter
	printersAttached int
}

func configurePacketOutput(
	out io.Writer,
	tree *dcdtree.DecodeTree,
	opts options,
) packetOutput {
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

	return packetOutput{
		genPrinter:       genPrinter,
		genAdapter:       genAdapter,
		printersAttached: printersAttached,
	}
}

func configureDecodeMode(
	out io.Writer,
	builder *snapshot.DecodeTreeBuilder,
	reader *snapshot.Reader,
	genPrinter *printers.GenericElementPrinter,
	opts options,
) ([]mappedRange, error) {
	mapped := []mappedRange{}

	if !opts.decode {
		return mapped, nil
	}

	mapper := builder.MemoryMapper()
	if mapper == nil {
		return nil, errors.New("trace packet lister: decode mode requires a memory mapper")
	}

	if opts.memCacheDisable {
		if err := mapper.EnableCaching(false); err != nil {
			return nil, fmt.Errorf("trace packet lister: configure memory cache disable=true failed: %w", err)
		}
	} else {
		if err := mapper.EnableCaching(true); err != nil {
			return nil, fmt.Errorf("trace packet lister: configure memory cache disable=false failed: %w", err)
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
				return nil, fmt.Errorf(
					"trace packet lister: configure memory cache sizes page_size=%d page_num=%d failed: %w",
					pageSize, numPages, err,
				)
			}
		}
	}

	var err error
	mapped, err = mapMemoryRanges(mapper, opts.ssDir, reader)
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(out, "Trace Packet Lister : Set trace element decode printer")
	if opts.testWaits > 0 {
		genPrinter.SetTestWaits(opts.testWaits)
	}
	if opts.profile {
		genPrinter.SetMute(true)
		genPrinter.SetCollectStats()
	}
	printMappedRanges(out, mapped)

	return mapped, nil
}

func runSingleSession(
	out io.Writer,
	tree *dcdtree.DecodeTree,
	fileName string,
	sink *filteredGenElemPrinter,
	genPrinter *printers.GenericElementPrinter,
	opts options,
) error {
	return processInputFilePull(out, tree, fileName, sink, genPrinter, opts)
}

func runMultiSession(
	out io.Writer,
	reader *snapshot.Reader,
	tree *dcdtree.DecodeTree,
	sourceNames []string,
	sink *filteredGenElemPrinter,
	genPrinter *printers.GenericElementPrinter,
	opts options,
) error {
	total := len(sourceNames)
	for i, sourceName := range sourceNames {
		fmt.Fprintf(out, "####### Multi Session decode: Buffer %d of %d; Source name = %s.\n\n", i+1, total, sourceName)
		srcTree, ok := reader.SourceTrees[sourceName]
		if !ok || srcTree == nil || srcTree.BufferInfo == nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s - buffer not found. Aborting.\n\n", sourceName)
			break
		}
		binFile := filepath.Join(reader.SnapshotPath, srcTree.BufferInfo.DataFileName)
		if err := processInputFilePull(out, tree, binFile, sink, genPrinter, opts); err != nil {
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

func drainTreeElementsToSink(tree *dcdtree.DecodeTree, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter) error {
	if tree == nil || sink == nil {
		return nil
	}

	var retErr error
	tree.Elements()(func(elem *ocsd.TraceElement, err error) bool {
		if err != nil {
			if errors.Is(err, ocsd.ErrWait) {
				// Queue is empty, wait for more bytes. This is normal!
				return false
			}
			retErr = err
			return false
		}
		if elem == nil {
			return true
		}
		if err := sink.PrintElement(elem); err != nil {
			if ocsd.IsDataWaitErr(err) {
				if genPrinter != nil && genPrinter.NeedAckWait() {
					genPrinter.AckWait()
				}
				return true
			}
			if !ocsd.IsDataContErr(err) {
				retErr = err
				return false
			}
		}
		return true
	})
	return retErr
}

func drainTreeElementsToSinkUntilEOF(tree *dcdtree.DecodeTree, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter) error {
	if tree == nil || sink == nil {
		return nil
	}

	for {
		elem, err := tree.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if errors.Is(err, ocsd.ErrWait) {
				continue
			}
			return err
		}
		if elem == nil {
			continue
		}
		if err := sink.PrintElement(elem); err != nil {
			if ocsd.IsDataWaitErr(err) {
				if genPrinter != nil && genPrinter.NeedAckWait() {
					genPrinter.AckWait()
				}
				continue
			}
			if !ocsd.IsDataContErr(err) {
				return err
			}
		}
	}
}

var _ = drainTreeElementsToSinkUntilEOF

func finalizeProcessedInput(tree *dcdtree.DecodeTree, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options) error {
	if err := tree.Close(); err != nil {
		return fmt.Errorf("trace packet lister: OpEOT error: %w", err)
	}
	if err := drainTreeElementsToSink(tree, sink, genPrinter); err != nil {
		return fmt.Errorf("trace packet lister: post-EOT element drain error: %w", err)
	}

	if opts.multiSession {
		if err := tree.Reset(0); err != nil {
			return fmt.Errorf("trace packet lister: OpReset error: %w", err)
		}
		if err := drainTreeElementsToSink(tree, sink, genPrinter); err != nil {
			return fmt.Errorf("trace packet lister: post-reset element drain error: %w", err)
		}
	}
	return nil
}

func reportProcessedInput(out io.Writer, traceIndex uint32, start time.Time, genPrinter *printers.GenericElementPrinter, opts options) {
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
}

func runSharedReaderPipeline(out io.Writer, tree *dcdtree.DecodeTree, in io.Reader, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options, start time.Time, align int, isFramed bool) error {
	if err := drainPreInputElements(tree, sink, genPrinter); err != nil {
		return err
	}

	buf := make([]byte, 1024)
	var footer [8]byte

	// Instantiate the session state object once.
	session := &decodeSession{
		tree:       tree,
		sink:       sink,
		genPrinter: genPrinter,
		align:      align,
		isFramed:   isFramed,
		pending:    make([]byte, 0, 2048),
		traceIndex: 0,
		err:        nil,
	}

	// Execute the loop
	if err := session.readLoop(out, in, buf, footer[:], opts); err != nil {
		return err
	}

	// Flush leftovers
	session.flushTail()

	// Validate final state
	if err := validateLegacyReadState(session.pending, session.traceIndex, session.err, session.align, session.isFramed); err != nil {
		return err
	}

	if err := finalizeProcessedInput(tree, sink, genPrinter, opts); err != nil {
		return err
	}

	reportProcessedInput(out, session.traceIndex, start, genPrinter, opts)
	return nil
}

func runDirectReaderPipeline(out io.Writer, tree *dcdtree.DecodeTree, in io.Reader, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options, start time.Time) error {
	if err := drainPreInputElements(tree, sink, genPrinter); err != nil {
		return err
	}

	countingIn := &countingReader{r: in}
	if err := tree.AttachReader(countingIn); err != nil {
		return fmt.Errorf("trace packet lister: attach direct reader: %w", err)
	}

	if err := drainTreeElementsToSinkUntilEOF(tree, sink, genPrinter); err != nil {
		return fmt.Errorf("trace packet lister: direct reader element drain error: %w", err)
	}

	if opts.multiSession {
		if err := tree.Reset(0); err != nil {
			return fmt.Errorf("trace packet lister: OpReset error: %w", err)
		}
		if err := drainTreeElementsToSink(tree, sink, genPrinter); err != nil {
			return fmt.Errorf("trace packet lister: post-reset element drain error: %w", err)
		}
	}

	reportProcessedInput(out, countingIn.Count(), start, genPrinter, opts)
	return nil
}

func readLegacyDStreamFooter(out io.Writer, in io.Reader, footer []byte, opts options) error {
	_, ferr := io.ReadFull(in, footer)
	if ferr == nil && opts.outRawPacked {
		fmt.Fprint(out, "DSTREAM footer [")
		for _, b := range footer {
			fmt.Fprintf(out, "0x%x ", b)
		}
		fmt.Fprintln(out, "]")
	}
	if ferr == io.EOF || ferr == io.ErrUnexpectedEOF {
		return ferr
	}
	return ferr
}

func validateLegacyReadState(pending []byte, traceIndex uint32, dataPathErr error, align int, isFramed bool) error {
	if dataPathErr != nil && ocsd.DataRespIsFatal(ocsd.DataRespFromErr(dataPathErr)) {
		return fatalDataPathError(ocsd.DataRespFromErr(dataPathErr), traceIndex, len(pending))
	}

	if dataPathErr != nil {
		return fmt.Errorf("trace packet lister: data path processing error: %w", dataPathErr)
	}

	if isFramed && len(pending) > 0 {
		return framedTailError(traceIndex, len(pending), align)
	}

	return nil
}

func processInputFilePull(out io.Writer, tree *dcdtree.DecodeTree, fileName string, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options) error {
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("trace packet lister: error: unable to open trace buffer %s: %w", fileName, err)
	}
	defer file.Close()

	return processInputFilePullReader(out, tree, file, sink, genPrinter, opts)
}

func processInputFilePullReader(out io.Writer, tree *dcdtree.DecodeTree, in io.Reader, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options) error {
	return processInputFilePullReaderBody(out, tree, in, sink, genPrinter, opts)
}

type decodeSession struct {
	tree       *dcdtree.DecodeTree
	sink       *filteredGenElemPrinter
	genPrinter *printers.GenericElementPrinter
	align      int
	isFramed   bool

	pending    []byte
	traceIndex uint32
	err        error
}

func (s *decodeSession) writeChunk(chunk []byte) uint32 {
	used, err := s.tree.Write(ocsd.TrcIndex(s.traceIndex), chunk)
	s.err = err
	return used
}

func (s *decodeSession) consume(used uint32) {
	if used > 0 {
		n := copy(s.pending, s.pending[used:])
		s.pending = s.pending[:n]
		s.traceIndex += used
	}
}

func (s *decodeSession) drainOutput() error {
	if err := drainTreeElementsToSink(s.tree, s.sink, s.genPrinter); err != nil {
		return err
	}
	return nil
}

func (s *decodeSession) flushWait() error {
	if err := s.tree.Flush(); err != nil {
		return fmt.Errorf("flush after wait: %w", err)
	}
	if err := drainTreeElementsToSink(s.tree, s.sink, s.genPrinter); err != nil {
		return fmt.Errorf("drain generic elements after flush: %w", err)
	}
	return nil
}

func (s *decodeSession) processPending() error {
	for len(s.pending) > 0 {
		sendLen := len(s.pending)
		if s.isFramed {
			sendLen -= sendLen % s.align
			if sendLen == 0 {
				break
			}
		}

		used := s.writeChunk(s.pending[:sendLen])

		if s.err != nil {
			if !ocsd.DataRespIsFatal(ocsd.DataRespFromErr(s.err)) {
				return s.err
			}
		}

		if err := s.drainOutput(); err != nil {
			return fmt.Errorf("drain generic elements: %w", err)
		}

		s.consume(used)

		if s.err != nil && ocsd.DataRespIsFatal(ocsd.DataRespFromErr(s.err)) {
			return s.err
		}

		if errors.Is(s.err, ocsd.ErrWait) {
			if err := s.flushWait(); err != nil {
				return err
			}
			continue
		}

		if used == 0 {
			break
		}
		if !s.isFramed {
			continue
		}
	}

	return s.err
}

func (s *decodeSession) feedChunk(chunk []byte) (bool, error) {
	s.pending = append(s.pending, chunk...)
	err := s.processPending()

	if err != nil && ocsd.DataRespIsFatal(ocsd.DataRespFromErr(err)) {
		return true, err
	}
	return false, err
}

func (s *decodeSession) flushTail() {
	if !ocsd.DataRespIsFatal(ocsd.DataRespFromErr(s.err)) && len(s.pending) > 0 && !s.isFramed {
		s.err = s.processPending()
	}
}

func (s *decodeSession) readIteration(out io.Writer, in io.Reader, buf []byte, footer []byte, opts options) (bool, error) {
	n, err := readLegacyInputChunk(in, buf, opts)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		n = max(n, 0)
	} else if err != nil {
		return false, err
	}

	var done bool
	if n > 0 {
		done, s.err = s.feedChunk(buf[:n])
		if done {
			return true, nil
		}
	}

	if opts.dstreamFormat {
		if err = readLegacyDStreamFooter(out, in, footer, opts); err != nil {
			return false, err
		}
	}

	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return false, err
	}

	return false, nil
}

func (s *decodeSession) readLoop(out io.Writer, in io.Reader, buf []byte, footer []byte, opts options) error {
	for !ocsd.DataRespIsFatal(ocsd.DataRespFromErr(s.err)) {
		done, err := s.readIteration(out, in, buf, footer, opts)
		if done {
			return nil
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func processInputFilePullReaderBody(out io.Writer, tree *dcdtree.DecodeTree, in io.Reader, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options) error {
	start := time.Now()

	if canUseDirectReaderDecodeOnly(tree, opts) {
		return runDirectReaderPipeline(out, tree, in, sink, genPrinter, opts, start)
	}

	align := frameAlignment(tree)
	isFramed := tree.FrameDeformatter() != nil

	return runSharedReaderPipeline(out, tree, in, sink, genPrinter, opts, start, align, isFramed)
}

func drainPreInputElements(tree *dcdtree.DecodeTree, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter) error {
	if err := drainTreeElementsToSink(tree, sink, genPrinter); err != nil {
		return fmt.Errorf("trace packet lister: pre-data element drain error: %w", err)
	}
	return nil
}

func readLegacyInputChunk(in io.Reader, buf []byte, opts options) (int, error) {
	if opts.dstreamFormat {
		n, err := io.ReadFull(in, buf[:512-8])
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return max(n, 0), err
		}
		return n, err
	}

	n, err := in.Read(buf)
	return n, err
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

func canUseDirectReaderDecodeOnly(tree *dcdtree.DecodeTree, opts options) bool {
	if tree == nil {
		return false
	}
	if !opts.decode {
		return false
	}
	if tree.FrameDeformatter() != nil {
		return false
	}
	if !tree.CanAttachReader() {
		return false
	}

	ok := true
	tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
		if !ok || elem == nil {
			return
		}
		switch elem.DataIn.(type) {
		case *stm.PktProc, *ptm.PktProc:
			// allow full decode direct-reader for STM and PTM
		case *etmv3.PktProc, *etmv4.Processor:
			if !opts.decodeOnly {
				ok = false
			}
		default:
			ok = false
		}
	})
	return ok
}

func attachPacketPrinters(out io.Writer, tree *dcdtree.DecodeTree, opts options) int {
	attached := 0
	idFilter := makeIDSet(opts.idList)
	showRawBytes := opts.decode || opts.pktMon

	type rawMonitorSetter interface {
		SetPktRawMonitor(ocsd.PacketMonitor)
	}

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

		if !opts.allSourceIDs && !idFilter[csID] {
			continue
		}

		protocolName := elem.DecoderTypeName
		mon := &genericRawPrinter{
			writer:       out,
			id:           csID,
			showRawBytes: showRawBytes,
		}

		if setter, ok := elem.DataIn.(rawMonitorSetter); ok {
			setter.SetPktRawMonitor(mon)
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

// help printing moved to config.go

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
