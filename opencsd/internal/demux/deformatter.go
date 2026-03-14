package demux

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

type outData struct {
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
	rawChanEnable  [128]bool

	// Datapath Attachments
	idStreams     [128]interfaces.TrcDataIn
	rawTraceFrame interfaces.TrcRawFrameIn
	errorLogger   common.ErrorLogger

	// state params
	trcCurrIdx  ocsd.TrcIndex
	frameSynced bool
	firstData   bool
	currSrcID   uint8

	exFrmNBytes    uint32
	bFsyncStartEob bool
	trcCurrIdxSof  ocsd.TrcIndex

	exFrmData [ocsd.DfrmtrFrameSize]byte

	inBlockBase      []byte // The block being processed (input block)
	inBlockProcessed uint32

	outData      [16]outData
	outDataIdx   uint32
	outProcessed uint32
	highestResp  ocsd.DatapathResp

	pendingData  []byte
	pendingIndex ocsd.TrcIndex
}

func NewFrameDeformatter() *FrameDeformatter {
	d := &FrameDeformatter{}
	d.resetStateParams()
	d.SetRawChanFilterAll(true)
	return d
}

// Attachments
func (d *FrameDeformatter) SetIDStream(id uint8, stream interfaces.TrcDataIn) {
	if id < 128 {
		d.idStreams[id] = stream
	}
}

func (d *FrameDeformatter) SetRawTraceFrame(stream interfaces.TrcRawFrameIn) {
	d.rawTraceFrame = stream
}

func (d *FrameDeformatter) SetErrorLogger(logger common.ErrorLogger) {
	d.errorLogger = logger
}

func (d *FrameDeformatter) Configure(flags uint32) ocsd.Err {
	err := ocsd.OK

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

	if err != ocsd.OK {
		if d.errorLogger != nil {
			errObj := common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "Invalid Config Flags")
			d.errorLogger.LogError(errObj)
		}
	} else {
		// alignment is the multiple of bytes the buffer size must be.
		d.cfgFlags = flags

		// using memory aligned buffers, the formatter always outputs 16 byte frames so enforce
		// this on the input
		d.alignment = 16
		// if we have HSYNCS then always align to 2 byte buffers
		if flags&ocsd.DfrmtrHasHsyncs != 0 {
			d.alignment = 2
		} else if flags&ocsd.DfrmtrHasFsyncs != 0 { // otherwise FSYNCS only can have 4 byte aligned buffers.
			d.alignment = 4
		}
	}
	return err
}

func (d *FrameDeformatter) GetConfigFlags() uint32 {
	return d.cfgFlags
}

func (d *FrameDeformatter) OutputFilterIDs(idList []uint8, enable bool) ocsd.Err {
	for _, id := range idList {
		if id > 128 {
			return ocsd.ErrInvalidID
		}
		// m_IDStreams[id].set_enabled(enable) is handled in attach pt but for here we use a simple routing if absent
		d.rawChanEnable[id] = enable
	}
	return ocsd.OK
}

func (d *FrameDeformatter) OutputFilterAllIDs(enable bool) ocsd.Err {
	d.SetRawChanFilterAll(enable)
	return ocsd.OK
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

func (d *FrameDeformatter) initCollateDataPathResp() {
	d.highestResp = ocsd.RespCont
}

func (d *FrameDeformatter) collateDataPathResp(resp ocsd.DatapathResp) {
	if resp > d.highestResp {
		d.highestResp = resp
	}
}

func (d *FrameDeformatter) dataPathCont() bool {
	return ocsd.DataRespIsCont(d.highestResp)
}

func (d *FrameDeformatter) outputRawMonBytes(op ocsd.DatapathOp, index ocsd.TrcIndex, frameElem ocsd.RawframeElem, data []byte, traceID uint8) {
	if d.rawTraceFrame != nil {
		d.rawTraceFrame.TraceRawFrameIn(op, index, frameElem, data, traceID)
	}
}

func (d *FrameDeformatter) executeNoneDataOpAllIDs(op ocsd.DatapathOp, index ocsd.TrcIndex) ocsd.DatapathResp {
	for id := range 128 {
		if d.idStreams[id] != nil { // if attached
			_, resp, err := d.idStreams[id].TraceDataIn(op, index, nil)
			d.collateDataPathResp(resp)
			if err != nil {
				d.collateDataPathResp(ocsd.RespFatalInvalidData)
				if d.errorLogger != nil {
					if e, ok := err.(*common.Error); ok {
						d.errorLogger.LogError(e)
					} else {
						d.errorLogger.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrFail, err.Error()))
					}
				}
			}
		}
	}

	if d.rawTraceFrame != nil {
		d.rawTraceFrame.TraceRawFrameIn(op, 0, ocsd.FrmNone, nil, 0)
	}
	return d.highestResp
}

func (d *FrameDeformatter) Reset() ocsd.DatapathResp {
	d.resetStateParams()
	d.initCollateDataPathResp()
	return d.executeNoneDataOpAllIDs(ocsd.OpReset, 0)
}

func (d *FrameDeformatter) Flush() ocsd.DatapathResp {
	d.executeNoneDataOpAllIDs(ocsd.OpFlush, 0)
	if d.dataPathCont() {
		d.outputFrame()
	}
	return d.highestResp
}

func (d *FrameDeformatter) resetStateParams() {
	// overall dynamic state - intra frame
	d.trcCurrIdx = ocsd.BadTrcIndex
	d.frameSynced = false
	d.firstData = false
	d.currSrcID = ocsd.BadCSSrcID

	// current frame processing
	d.exFrmNBytes = 0
	d.bFsyncStartEob = false
	d.trcCurrIdxSof = ocsd.BadTrcIndex

	d.pendingData = nil
	d.pendingIndex = ocsd.BadTrcIndex
}

// TraceDataIn implementation
func (d *FrameDeformatter) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	resp := ocsd.RespFatalInvalidOp
	d.initCollateDataPathResp()

	d.outPackedRaw = d.rawTraceFrame != nil && (d.cfgFlags&ocsd.DfrmtrPackedRawOut) != 0
	d.outUnpackedRaw = d.rawTraceFrame != nil && (d.cfgFlags&ocsd.DfrmtrUnpackedRawOut) != 0

	var numBytesProcessed uint32
	var err error

	switch op {
	case ocsd.OpReset:
		resp = d.Reset()
	case ocsd.OpFlush:
		resp = d.Flush()
	case ocsd.OpEOT:
		resp = d.executeNoneDataOpAllIDs(ocsd.OpEOT, 0)
	case ocsd.OpData:
		if len(dataBlock) == 0 {
			resp = ocsd.RespFatalInvalidParam
		} else {
			resp = d.processTraceData(index, dataBlock, &numBytesProcessed)
		}
	default:
		// Unsupported operations
	}

	return numBytesProcessed, resp, err
}

func (d *FrameDeformatter) processTraceData(index ocsd.TrcIndex, dataBlock []byte, numBytesProcessed *uint32) (resp ocsd.DatapathResp) {
	if d.alignment == 0 {
		errObj := common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrFail, "Deformatter not configured")
		return d.processTraceDataError(errObj, ocsd.RespFatalSysErr)
	}

	if len(d.pendingData) > 0 {
		expected := d.pendingIndex + ocsd.TrcIndex(len(d.pendingData))
		if expected != index {
			return d.processTraceDataError(common.NewErrorWithIdxMsg(ocsd.ErrSevError, ocsd.ErrDfrmtrNotconttrace, index, "Not continuous trace data"), ocsd.RespFatalInvalidData)
		}
	} else if d.firstData {
		if d.trcCurrIdx != index {
			return d.processTraceDataError(common.NewErrorWithIdxMsg(ocsd.ErrSevError, ocsd.ErrDfrmtrNotconttrace, index, "Not continuous trace data"), ocsd.RespFatalInvalidData)
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
		*numBytesProcessed = uint32(len(dataBlock))
		return d.highestResp
	}

	alignedBlock := d.pendingData[:processSize]
	alignedIndex := d.pendingIndex

	var alignedProcessed uint32
	resp = d.processTraceDataAligned(alignedIndex, alignedBlock, &alignedProcessed)

	if alignedProcessed > 0 {
		d.pendingData = d.pendingData[int(alignedProcessed):]
		d.pendingIndex += ocsd.TrcIndex(alignedProcessed)
		if len(d.pendingData) == 0 {
			d.pendingIndex = ocsd.BadTrcIndex
		}
	}

	if !d.firstData {
		d.firstData = true
	}

	*numBytesProcessed = uint32(len(dataBlock))
	resp = d.highestResp
	return
}

func (d *FrameDeformatter) processTraceDataAligned(index ocsd.TrcIndex, dataBlock []byte, numBytesProcessed *uint32) (resp ocsd.DatapathResp) {
	d.trcCurrIdx = index

	// record incoming block
	d.inBlockBase = dataBlock
	d.inBlockProcessed = 0
	dataBlockSize := uint32(len(dataBlock))

	if dataBlockSize%d.alignment != 0 {
		return d.processTraceDataError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, fmt.Sprintf("Input block incorrect size, must be %d byte multiple", d.alignment)), ocsd.RespFatalInvalidData)
	}

	if d.checkForSync(dataBlockSize) {
		bProcessing := true
		for bProcessing {
			var errObj *common.Error
			bProcessing, errObj = d.extractFrame(dataBlockSize)
			if errObj != nil {
				return d.processTraceDataError(errObj, ocsd.RespFatalInvalidData)
			}
			if bProcessing {
				bProcessing = d.unpackFrame()
			}
			if bProcessing {
				bProcessing = d.outputFrame()
			}
		}
	}

	*numBytesProcessed = d.inBlockProcessed
	resp = d.highestResp
	return
}

func (d *FrameDeformatter) processTraceDataError(errObj *common.Error, resp ocsd.DatapathResp) ocsd.DatapathResp {
	d.collateDataPathResp(resp)
	if errObj != nil && d.errorLogger != nil {
		d.errorLogger.LogError(errObj)
	}
	return d.highestResp
}
