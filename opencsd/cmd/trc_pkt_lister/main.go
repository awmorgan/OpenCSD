package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"opencsd/internal/dcdtree"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
)

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

func executeDecodePipeline(
	reader *snapshot.Reader,
	p *decodePipeline,
	sourceNames []string,
	opts options,
) error {
	if err := configureDecodeMode(p.streamOut, p.builder, reader, p.genPrinter, opts); err != nil {
		return err
	}

	if !opts.decode && p.printersAttached == 0 {
		fmt.Fprintln(p.streamOut, "Trace Packet Lister : No supported protocols found.")
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
