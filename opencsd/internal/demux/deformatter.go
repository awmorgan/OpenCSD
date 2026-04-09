package demux

import (
	"fmt"

	"opencsd/internal/ocsd"
)

type outDataEntry struct {
	id    uint8
	valid uint32
	index ocsd.TrcIndex
	used  uint32
	data  [16]byte
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
}

func NewFrameDeformatter() *FrameDeformatter {
	d := &FrameDeformatter{
		rawChanEnable: make([]bool, 128),
		idStreams:     make([]ocsd.TraceDecoder, 128),
	}
	d.resetStateParams()
	d.SetRawChanFilterAll(true)
	return d
}

// Attachments
func (d *FrameDeformatter) SetIDStream(id uint8, stream ocsd.TraceDecoder) {
	if id < 128 {
		d.idStreams[id] = stream
	}
}

func (d *FrameDeformatter) SetRawTraceFrame(stream ocsd.RawFrameProcessor) {
	d.rawTraceFrame = stream
}

func (d *FrameDeformatter) Configure(flags uint32) error {
	var err error

	if (flags & ^uint32(ocsd.DfrmtrValidMask)) != 0 {
		err = ocsd.ErrInvalidParamVal
	}

	if (flags & ocsd.DfrmtrValidMask) == 0 {
		err = ocsd.ErrInvalidParamVal
	}

	if (flags&(ocsd.DfrmtrHasFsyncs|ocsd.DfrmtrHasHsyncs) != 0) &&
		(flags&ocsd.DfrmtrFrameMemAlign != 0) {
		err = ocsd.ErrInvalidParamVal
	}

	if err == nil {
		// alignment is the multiple of bytes the buffer size must be.
		d.cfgFlags = flags

		// using memory aligned buffers, the formatter always outputs 16 byte frames so enforce
		// this on the input
		d.alignment = 16
		// if we have HSYNCS then always align to 2 byte buffers
		if flags&ocsd.DfrmtrHasHsyncs != 0 {
			d.alignment = 2
		} else if flags&ocsd.DfrmtrHasFsyncs != 0 { // otherwise Fsyncs only can have 4 byte aligned buffers.
			d.alignment = 4
		}
	}
	return err
}

func (d *FrameDeformatter) ConfigFlags() uint32 {
	return d.cfgFlags
}

func (d *FrameDeformatter) OutputFilterIDs(idList []uint8, enable bool) error {
	for _, id := range idList {
		if id >= 128 {
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
	if id < 128 {
		return d.rawChanEnable[id]
	}
	return false
}

// Decode control

func (d *FrameDeformatter) outputRawMonBytes(index ocsd.TrcIndex, frameElem ocsd.RawframeElem, data []byte, traceID uint8) {
	if d.rawTraceFrame != nil {
		_ = d.rawTraceFrame.WriteRawFrame(index, frameElem, data, traceID)
	}
}

func (d *FrameDeformatter) callIDStream(stream ocsd.TraceDecoder, op ocsd.DatapathOp, index ocsd.TrcIndex, data []byte) (uint32, error) {
	if stream == nil {
		return 0, nil
	}
	switch op {
	case ocsd.OpData:
		return stream.Write(index, data)
	case ocsd.OpEOT:
		return 0, stream.Close()
	case ocsd.OpFlush:
		return 0, stream.Flush()
	case ocsd.OpReset:
		return 0, stream.Reset(index)
	default:
		return 0, ocsd.ErrInvalidParamVal
	}
}

func (d *FrameDeformatter) flushAllIDs() error {
	var outErr error

	for _, stream := range d.idStreams {
		if stream != nil { // if attached
			_, err := d.callIDStream(stream, ocsd.OpFlush, 0, nil)
			if err != nil && outErr == nil {
				outErr = err
			}
		}
	}

	if d.rawTraceFrame != nil {
		err := d.rawTraceFrame.FlushRawFrames()
		if err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

func (d *FrameDeformatter) resetAllIDs(index ocsd.TrcIndex) error {
	var outErr error

	for _, stream := range d.idStreams {
		if stream != nil { // if attached
			_, err := d.callIDStream(stream, ocsd.OpReset, index, nil)
			if err != nil && outErr == nil {
				outErr = err
			}
		}
	}

	if d.rawTraceFrame != nil {
		err := d.rawTraceFrame.ResetRawFrames()
		if err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

func (d *FrameDeformatter) closeAllIDs() error {
	var outErr error

	for _, stream := range d.idStreams {
		if stream != nil { // if attached
			_, err := d.callIDStream(stream, ocsd.OpEOT, 0, nil)
			if err != nil && outErr == nil {
				outErr = err
			}
		}
	}

	if d.rawTraceFrame != nil {
		err := d.rawTraceFrame.CloseRawFrames()
		if err != nil && outErr == nil {
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
	if cap(d.exFrmData) < int(ocsd.DfrmtrFrameSize) {
		d.exFrmData = make([]byte, ocsd.DfrmtrFrameSize)
	} else {
		d.exFrmData = d.exFrmData[:ocsd.DfrmtrFrameSize]
	}

	d.pendingData = nil
	d.pendingIndex = ocsd.BadTrcIndex
	if cap(d.outData) < 16 {
		d.outData = make([]outDataEntry, 16)
	} else {
		d.outData = d.outData[:16]
	}
}

// TraceDataIn implementation
func (d *FrameDeformatter) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	switch op {
	case ocsd.OpReset:
		return 0, d.Reset(index)
	case ocsd.OpFlush:
		return 0, d.Flush()
	case ocsd.OpEOT:
		return 0, d.Close()
	case ocsd.OpData:
		return d.Write(index, dataBlock)
	default:
		return 0, ocsd.ErrInvalidParamVal
	}
}

// Write is the explicit data entrypoint implementing TrcDataProcessorExplicit.
func (d *FrameDeformatter) Write(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	d.outPackedRaw = d.rawTraceFrame != nil && (d.cfgFlags&ocsd.DfrmtrPackedRawOut) != 0
	d.outUnpackedRaw = d.rawTraceFrame != nil && (d.cfgFlags&ocsd.DfrmtrUnpackedRawOut) != 0
	if len(dataBlock) == 0 {
		return 0, ocsd.ErrInvalidParamVal
	}
	return d.processTraceData(index, dataBlock)
}

// Close forwards an EOT operation through the legacy multiplexer.
func (d *FrameDeformatter) Close() error {
	d.outPackedRaw = d.rawTraceFrame != nil && (d.cfgFlags&ocsd.DfrmtrPackedRawOut) != 0
	d.outUnpackedRaw = d.rawTraceFrame != nil && (d.cfgFlags&ocsd.DfrmtrUnpackedRawOut) != 0
	return d.closeAllIDs()
}

func (d *FrameDeformatter) processTraceData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	if d.alignment == 0 {
		return 0, fmt.Errorf("%w: Deformatter not configured", ocsd.ErrFail)
	}

	if len(d.pendingData) > 0 {
		expected := d.pendingIndex + ocsd.TrcIndex(len(d.pendingData))
		if expected != index {
			err := fmt.Errorf("%w: Not continuous trace data", ocsd.ErrDfrmtrNotconttrace)
			return 0, err
		}
	} else if d.firstData {
		if d.trcCurrIdx != index {
			err := fmt.Errorf("%w: Not continuous trace data", ocsd.ErrDfrmtrNotconttrace)
			return 0, err
		}
	}
	if len(d.pendingData) == 0 {
		d.pendingIndex = index
	}
	d.pendingData = append(d.pendingData, dataBlock...)

	dataBlockSize := uint32(len(d.pendingData))
	processSize := dataBlockSize - (dataBlockSize % d.alignment)

	if processSize == 0 {
		if !d.firstData {
			d.firstData = true
		}
		return uint32(len(dataBlock)), nil
	}

	alignedBlock := d.pendingData[:processSize]
	alignedIndex := d.pendingIndex

	var alignedProcessed uint32
	var outErr error
	alignedProcessed, outErr = d.processTraceDataAligned(alignedIndex, alignedBlock)

	if alignedProcessed > 0 {
		d.pendingData = d.pendingData[int(alignedProcessed):]
		d.pendingIndex += ocsd.TrcIndex(alignedProcessed)
		if len(d.pendingData) == 0 {
			d.pendingData = nil
			d.pendingIndex = ocsd.BadTrcIndex
		}
	}

	if !d.firstData {
		d.firstData = true
	}

	numBytesProcessed := uint32(len(dataBlock))
	return numBytesProcessed, outErr
}

func (d *FrameDeformatter) processTraceDataAligned(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	d.trcCurrIdx = index

	// record incoming block
	d.inBlockBase = dataBlock
	d.inBlockProcessed = 0
	dataBlockSize := uint32(len(dataBlock))
	var outErr error

	if dataBlockSize%d.alignment != 0 {
		return 0, fmt.Errorf("%w: Input block incorrect size, must be %d byte multiple", ocsd.ErrInvalidParamVal, d.alignment)
	}

	if d.checkForSync(dataBlockSize) {
		bProcessing := true
		for bProcessing {
			var frameErr error
			bProcessing, frameErr = d.extractFrame(dataBlockSize)
			if frameErr != nil && outErr == nil {
				outErr = frameErr
			}
			if outErr != nil {
				break
			}
			if bProcessing {
				bProcessing = d.unpackFrame()
			}
			if bProcessing {
				bProcessing, outErr = d.outputFrame(outErr)
				if outErr != nil {
					break
				}
			}
		}
	}

	return d.inBlockProcessed, outErr
}
