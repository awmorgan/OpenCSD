package demux

import (
	"errors"
	"fmt"
	"io"

	"opencsd/internal/ocsd"
)

const (
	maxTraceID        = 128
	minOutDataEntries = 16
)

type outDataEntry struct {
	id    uint8
	valid uint32
	index ocsd.TrcIndex
	used  uint32
	data  [16]byte
}

func (e *outDataEntry) reset(id uint8, index ocsd.TrcIndex) {
	e.id = id
	e.valid = 0
	e.index = index
	e.used = 0
}

func (e *outDataEntry) appendByte(b byte) {
	e.data[e.valid] = b
	e.valid++
}

func (e *outDataEntry) bytes() []byte {
	return e.data[:e.valid]
}

func (e *outDataEntry) remaining() []byte {
	return e.data[e.used:e.valid]
}

func (e *outDataEntry) remainingIndex() ocsd.TrcIndex {
	return e.index + ocsd.TrcIndex(e.used)
}

// FrameDeformatter represents TraceFormatterFrameDecoder and its TraceFmtDcdImpl.
// It translates the CoreSight formatted trace byte stream into a demuxed packet stream per ID.
type FrameDeformatter struct {
	// configuration
	cfgFlags       uint32
	alignment      uint32
	forceSyncIdx   uint32
	useForceSync   bool
	outPackedRaw   bool
	outUnpackedRaw bool
	rawChanEnable  []bool

	// Datapath Attachments
	idStreams     []ocsd.TraceDecoder
	rawTraceFrame ocsd.RawFrameProcessor

	// state params
	trcCurrIdx  ocsd.TrcIndex
	frameSynced bool
	firstData   bool
	currSrcID   uint8

	exFrmBytes    uint32
	fsyncStartEOB bool
	trcCurrIdxSof ocsd.TrcIndex

	exFrmData []byte

	inBlockBase      []byte // The block being processed (input block)
	inBlockProcessed uint32

	outData      []outDataEntry
	outProcessed uint32

	pendingData  []byte
	pendingIndex ocsd.TrcIndex

	// Pull-mode source
	sourceReader io.Reader
	sourceIndex  ocsd.TrcIndex
	sourceEOF    bool
}

func NewFrameDeformatter() *FrameDeformatter {
	d := &FrameDeformatter{
		rawChanEnable: make([]bool, maxTraceID),
		idStreams:     make([]ocsd.TraceDecoder, maxTraceID),
	}
	d.resetStateParams()
	d.SetRawChanFilterAll(true)
	return d
}

// Attachments
func (d *FrameDeformatter) SetIDStream(id uint8, stream ocsd.TraceDecoder) {
	if validTraceID(id) {
		d.idStreams[id] = stream
	}
}

func (d *FrameDeformatter) SetRawTraceFrame(stream ocsd.RawFrameProcessor) {
	d.rawTraceFrame = stream
}

func (d *FrameDeformatter) Configure(flags uint32) error {
	if err := validateFormatterFlags(flags); err != nil {
		return err
	}

	d.cfgFlags = flags
	d.alignment = alignmentForFlags(flags)
	return nil
}

func validateFormatterFlags(flags uint32) error {
	if flags&^uint32(ocsd.DfrmtrValidMask) != 0 {
		return ocsd.ErrInvalidParamVal
	}
	if flags&ocsd.DfrmtrValidMask == 0 {
		return ocsd.ErrInvalidParamVal
	}
	if flags&ocsd.DfrmtrFrameMemAlign != 0 && flags&(ocsd.DfrmtrHasFsyncs|ocsd.DfrmtrHasHsyncs) != 0 {
		return ocsd.ErrInvalidParamVal
	}
	return nil
}

func alignmentForFlags(flags uint32) uint32 {
	switch {
	case flags&ocsd.DfrmtrHasHsyncs != 0:
		return 2
	case flags&ocsd.DfrmtrHasFsyncs != 0:
		return 4
	default:
		return ocsd.DfrmtrFrameSize
	}
}

func validTraceID(id uint8) bool {
	return id < maxTraceID
}

func (d *FrameDeformatter) ConfigFlags() uint32 {
	return d.cfgFlags
}

func (d *FrameDeformatter) OutputFilterIDs(idList []uint8, enable bool) error {
	for _, id := range idList {
		if !validTraceID(id) {
			return ocsd.ErrInvalidID
		}
		// m_IDStreams[id].set_enabled(enable) is handled in attach pt but for here we use a simple routing if absent
		d.rawChanEnable[id] = enable
	}
	return nil
}

func (d *FrameDeformatter) OutputFilterAllIDs(enable bool) error {
	d.SetRawChanFilterAll(enable)
	return nil
}

func (d *FrameDeformatter) SetRawChanFilterAll(enable bool) {
	for i := range d.rawChanEnable {
		d.rawChanEnable[i] = enable
	}
}

func (d *FrameDeformatter) rawChanEnabled(id uint8) bool {
	return validTraceID(id) && d.rawChanEnable[id]
}

// Decode control

func (d *FrameDeformatter) outputRawMonBytes(index ocsd.TrcIndex, frameElem ocsd.RawframeElem, data []byte, traceID uint8) {
	if d.rawTraceFrame != nil {
		_ = d.rawTraceFrame.WriteRawFrame(index, frameElem, data, traceID)
	}
}

func (d *FrameDeformatter) callIDStream(stream ocsd.TraceDecoder, index ocsd.TrcIndex, data []byte) (uint32, error) {
	if stream == nil {
		return 0, nil
	}
	return stream.Write(index, data)
}

func (d *FrameDeformatter) flushAllIDs() error {
	return d.controlAllIDs(
		func(stream ocsd.TraceDecoder) error { return stream.Flush() },
		func(raw ocsd.RawFrameProcessor) error { return raw.FlushRawFrames() },
	)
}

func (d *FrameDeformatter) resetAllIDs(index ocsd.TrcIndex) error {
	return d.controlAllIDs(
		func(stream ocsd.TraceDecoder) error { return stream.Reset(index) },
		func(raw ocsd.RawFrameProcessor) error { return raw.ResetRawFrames() },
	)
}

func (d *FrameDeformatter) closeAllIDs() error {
	return d.controlAllIDs(
		func(stream ocsd.TraceDecoder) error { return stream.Close() },
		func(raw ocsd.RawFrameProcessor) error { return raw.CloseRawFrames() },
	)
}

func (d *FrameDeformatter) controlAllIDs(
	streamOp func(ocsd.TraceDecoder) error,
	rawOp func(ocsd.RawFrameProcessor) error,
) error {
	var outErr error

	for _, stream := range d.idStreams {
		if stream == nil {
			continue
		}
		if err := streamOp(stream); err != nil && outErr == nil {
			outErr = err
		}
	}

	if d.rawTraceFrame != nil {
		if err := rawOp(d.rawTraceFrame); err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

func (d *FrameDeformatter) Reset(index ocsd.TrcIndex) error {
	d.resetStateParams()
	return d.resetAllIDs(index)
}

func (d *FrameDeformatter) Flush() error {
	outErr := d.flushAllIDs()
	if outErr == nil {
		_, outErr = d.outputFrame(outErr)
	}
	return outErr
}

func (d *FrameDeformatter) resetStateParams() {
	// overall dynamic state - intra frame
	d.trcCurrIdx = ocsd.BadTrcIndex
	d.frameSynced = false
	d.firstData = false
	d.currSrcID = ocsd.BadCSSrcID

	// current frame processing
	d.exFrmBytes = 0
	d.fsyncStartEOB = false
	d.trcCurrIdxSof = ocsd.BadTrcIndex
	d.exFrmData = ensureByteSlice(d.exFrmData, int(ocsd.DfrmtrFrameSize))

	d.pendingData = nil
	d.pendingIndex = ocsd.BadTrcIndex
	d.outData = ensureOutDataSlice(d.outData, minOutDataEntries)
}

func ensureByteSlice(buf []byte, size int) []byte {
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func ensureOutDataSlice(buf []outDataEntry, size int) []outDataEntry {
	if cap(buf) < size {
		return make([]outDataEntry, size)
	}
	return buf[:size]
}

// Write is the explicit data entrypoint implementing TrcDataProcessorExplicit.
func (d *FrameDeformatter) Write(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	d.updateRawOutputState()
	if len(dataBlock) == 0 {
		return 0, ocsd.ErrInvalidParamVal
	}
	return d.processTraceData(index, dataBlock)
}

// Close forwards an EOT operation through the legacy multiplexer.
func (d *FrameDeformatter) Close() error {
	d.updateRawOutputState()
	return d.closeAllIDs()
}

func (d *FrameDeformatter) updateRawOutputState() {
	d.outPackedRaw = d.rawTraceFrame != nil && d.cfgFlags&ocsd.DfrmtrPackedRawOut != 0
	d.outUnpackedRaw = d.rawTraceFrame != nil && d.cfgFlags&ocsd.DfrmtrUnpackedRawOut != 0
}

func (d *FrameDeformatter) processTraceData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	if d.alignment == 0 {
		return 0, fmt.Errorf("%w: Deformatter not configured", ocsd.ErrFail)
	}
	if err := d.checkContinuity(index); err != nil {
		return 0, err
	}

	d.appendPendingData(index, dataBlock)
	processSize := alignedPrefixLen(uint32(len(d.pendingData)), d.alignment)
	if processSize == 0 {
		d.firstData = true
		return uint32(len(dataBlock)), nil
	}

	alignedProcessed, outErr := d.processTraceDataAligned(d.pendingIndex, d.pendingData[:processSize])
	d.discardProcessedPendingData(alignedProcessed)
	d.firstData = true

	return uint32(len(dataBlock)), outErr
}

func (d *FrameDeformatter) checkContinuity(index ocsd.TrcIndex) error {
	if len(d.pendingData) > 0 {
		expected := d.pendingIndex + ocsd.TrcIndex(len(d.pendingData))
		if expected != index {
			return fmt.Errorf("%w: Not continuous trace data", ocsd.ErrDfrmtrNotconttrace)
		}
		return nil
	}

	if d.firstData && d.trcCurrIdx != index {
		return fmt.Errorf("%w: Not continuous trace data", ocsd.ErrDfrmtrNotconttrace)
	}
	return nil
}

func (d *FrameDeformatter) appendPendingData(index ocsd.TrcIndex, dataBlock []byte) {
	if len(d.pendingData) == 0 {
		d.pendingIndex = index
	}
	d.pendingData = append(d.pendingData, dataBlock...)
}

func alignedPrefixLen(size, alignment uint32) uint32 {
	return size - size%alignment
}

func (d *FrameDeformatter) discardProcessedPendingData(processed uint32) {
	if processed == 0 {
		return
	}

	d.pendingData = d.pendingData[int(processed):]
	d.pendingIndex += ocsd.TrcIndex(processed)
	if len(d.pendingData) == 0 {
		d.pendingData = nil
		d.pendingIndex = ocsd.BadTrcIndex
	}
}

func (d *FrameDeformatter) processTraceDataAligned(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	dataBlockSize := uint32(len(dataBlock))
	if dataBlockSize%d.alignment != 0 {
		return 0, fmt.Errorf("%w: Input block incorrect size, must be %d byte multiple", ocsd.ErrInvalidParamVal, d.alignment)
	}

	d.trcCurrIdx = index
	d.inBlockBase = dataBlock
	d.inBlockProcessed = 0

	if !d.checkForSync(dataBlockSize) {
		return d.inBlockProcessed, nil
	}

	for processing := true; processing; {
		var err error
		processing, err = d.extractFrame(dataBlockSize)
		if err != nil {
			return d.inBlockProcessed, err
		}
		if processing {
			processing = d.unpackFrame()
		}
		if processing {
			processing, err = d.outputFrame(nil)
			if err != nil {
				return d.inBlockProcessed, err
			}
		}
	}

	return d.inBlockProcessed, nil
}

// --- Pull Architecture Additions ---

// Stream bridges the push-based demuxer to a pull-based io.Reader.
// It implements ocsd.TraceDecoder to receive pushed data internally from the demuxer.
type Stream struct {
	demux *FrameDeformatter
	id    uint8
	buf   []byte
	eof   bool
}

func (s *Stream) Write(index ocsd.TrcIndex, data []byte) (uint32, error) {
	s.buf = append(s.buf, data...)
	return uint32(len(data)), nil
}

func (s *Stream) Close() error {
	s.eof = true
	return nil
}

func (s *Stream) Flush() error { return nil }

func (s *Stream) Reset(index ocsd.TrcIndex) error {
	s.buf = s.buf[:0]
	s.eof = false
	return nil
}

func (s *Stream) Read(p []byte) (int, error) {
	if err := s.fillUntilReady(); err != nil {
		return 0, err
	}
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	if s.eof || s.demux.sourceEOF {
		return 0, io.EOF
	}
	return 0, ocsd.ErrWait
}

func (s *Stream) fillUntilReady() error {
	for len(s.buf) == 0 && !s.eof && !s.demux.sourceEOF {
		err := s.demux.pullFromSource()
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, ocsd.ErrWait) {
			break
		}
		return err
	}
	return nil
}

// SetReader attaches a pull-style raw byte stream to the demuxer.
func (d *FrameDeformatter) SetReader(r io.Reader) {
	d.sourceReader = r
	d.sourceIndex = 0
	d.sourceEOF = false
}

// GetStream returns an io.Reader for a specific Trace ID, internally wiring it to the demuxer.
func (d *FrameDeformatter) GetStream(id uint8) io.Reader {
	s := &Stream{
		demux: d,
		id:    id,
	}
	d.SetIDStream(id, s)
	return s
}

func (d *FrameDeformatter) pullFromSource() error {
	if d.sourceReader == nil {
		return io.EOF
	}
	if d.alignment == 0 {
		return fmt.Errorf("%w: Deformatter not configured", ocsd.ErrFail)
	}

	bytesNeeded := int(d.alignment) - len(d.pendingData)
	if bytesNeeded <= 0 {
		// If we already have enough data to process an aligned block,
		// the caller can retry without pulling more bytes.
		return nil
	}

	buf := make([]byte, bytesNeeded)
	n, err := d.sourceReader.Read(buf)
	if n > 0 {
		if procErr := d.writePulledBytes(buf[:n]); procErr != nil {
			return procErr
		}
	}
	if errors.Is(err, io.EOF) && !d.sourceEOF {
		d.finishSource()
	}
	if n == 0 && err == nil {
		return ocsd.ErrWait
	}
	return err
}

func (d *FrameDeformatter) writePulledBytes(data []byte) error {
	_, err := d.Write(d.sourceIndex, data)
	d.sourceIndex += ocsd.TrcIndex(len(data))
	return err
}

func (d *FrameDeformatter) finishSource() {
	d.sourceEOF = true
	_ = d.Flush()
	_ = d.Close() // this sets eof=true on all registered Streams
}
