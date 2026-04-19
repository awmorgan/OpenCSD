package main

import (
	"errors"
	"fmt"
	"io"
	"opencsd/internal/dcdtree"
	"opencsd/internal/etmv3"
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/ptm"
	"opencsd/internal/stm"
	"os"
	"time"
)

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

func processInputFilePullReaderBody(out io.Writer, tree *dcdtree.DecodeTree, in io.Reader, sink *filteredGenElemPrinter, genPrinter *printers.GenericElementPrinter, opts options) error {
	start := time.Now()

	if canUseDirectReaderDecodeOnly(tree, opts) {
		return runDirectReaderPipeline(out, tree, in, sink, genPrinter, opts, start)
	}

	align := frameAlignment(tree)
	isFramed := tree.FrameDeformatter() != nil

	return runSharedReaderPipeline(out, tree, in, sink, genPrinter, opts, start, align, isFramed)
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
