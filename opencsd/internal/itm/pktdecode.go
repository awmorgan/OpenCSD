package itm

import (
	"errors"
	"fmt"
	"io"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type traceElemEvent struct {
	index   ocsd.TrcIndex
	traceID uint8
	elem    ocsd.TraceElement
}

type decoderState int

const (
	dcdNoSync decoderState = iota
	dcdWaitSync
	dcdDecodePkts
)

type stateFn func() (stateFn, ocsd.DatapathResp, bool)

// PktDecode decodes ITM packets into generic ITM-SW trace packets.
type PktDecode struct {
	Name         string
	traceElemOut ocsd.GenElemProcessor
	MemAccess    common.TargetMemAccess
	InstrDecode  common.InstrDecode
	IndexCurrPkt ocsd.TrcIndex
	Config       *Config
	CurrPacketIn *Packet

	currState decoderState

	itmInfo       ocsd.SWTItmInfo
	localTSCount  uint64
	globalTS      uint64
	stimPage      uint8
	needGTS2      bool
	prevOverflow  bool
	gtsFreqChange bool

	unsyncInfo ocsd.UnsyncInfo
	csID       uint8
	outputElem ocsd.TraceElement

	// Pull-iterator fields
	pendingElements []traceElemEvent
	collectElements bool
}

func (d *PktDecode) ApplyFlags(flags uint32) error { return nil }

// NewPktDecode creates a new ITM packet decoder.
func NewPktDecode(cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ITM config cannot be nil", ocsd.ErrInvalidParamVal)
	}

	instID := int(cfg.TraceID())
	d := &PktDecode{
		Name: fmt.Sprintf("DCD_ITM_%d", instID),
	}
	d.configureDecoder()
	if err := d.SetProtocolConfig(cfg); err != nil {
		return nil, err
	}
	return d, nil
}

// OutputTraceElement sends an element using IndexCurrPkt (or queues if in collect mode).
func (d *PktDecode) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error {
	if d.collectElements {
		e := traceElemEvent{d.IndexCurrPkt, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	if d.traceElemOut == nil {
		e := traceElemEvent{d.IndexCurrPkt, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	err := d.traceElemOut.TraceElemIn(d.IndexCurrPkt, traceID, elem)
	if ocsd.IsDataContErr(err) {
		return nil
	}
	if ocsd.IsDataWaitErr(err) {
		return ocsd.ErrWait
	}
	return err
}

// OutputTraceElementIdx sends an element at an explicit index.
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	if d.traceElemOut == nil {
		e := traceElemEvent{idx, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	err := d.traceElemOut.TraceElemIn(idx, traceID, elem)
	if ocsd.IsDataContErr(err) {
		return nil
	}
	if ocsd.IsDataWaitErr(err) {
		return ocsd.ErrWait
	}
	return err
}

// AccessMemory reads target memory.
func (d *PktDecode) AccessMemory(address ocsd.VAddr, traceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	if d.MemAccess != nil {
		return d.MemAccess.ReadTargetMemory(address, traceID, memSpace, reqBytes)
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

// InstrDecodeCall calls the attached instruction decoder.
func (d *PktDecode) InstrDecodeCall(instrInfo *ocsd.InstrInfo) error {
	if d.InstrDecode != nil {
		return d.InstrDecode.DecodeInstruction(instrInfo)
	}
	return ocsd.ErrDcdInterfaceUnused
}

// InvalidateMemAccCache invalidates the memory access cache.
func (d *PktDecode) InvalidateMemAccCache(traceID uint8) error {
	if d.MemAccess != nil {
		d.MemAccess.InvalidateMemAccCache(traceID)
		return nil
	}
	return ocsd.ErrDcdInterfaceUnused
}

// SetProtocolConfig sets the ITM hardware configuration.
func (d *PktDecode) SetProtocolConfig(cfg *Config) error {
	d.Config = cfg
	if d.Config == nil {
		return ocsd.ErrNotInit
	}
	d.csID = d.Config.TraceID()
	return nil
}

func (d *PktDecode) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	resp := ocsd.RespCont
	var err error
	switch op {
	case ocsd.OpData:
		if pktIn == nil {
			err = ocsd.ErrInvalidParamVal
			resp = ocsd.RespFatalInvalidParam
		} else {
			d.CurrPacketIn = pktIn
			d.IndexCurrPkt = indexSOP
			d.collectElements = true
			resp = d.ProcessPacket()
			d.collectElements = false
			// Drain queued elements only when using legacy push sink wiring.
			if ocsd.DataRespIsCont(resp) && d.traceElemOut != nil {
				err = nil
				for {
					_, _, _, nextErr := d.NextElement()
					if errors.Is(nextErr, io.EOF) {
						break
					}
					if nextErr != nil {
						err = nextErr
						resp = ocsd.DataRespFromErr(err)
						break
					}
				}
			}
		}
	case ocsd.OpEOT:
		resp = d.OnEOT()
	case ocsd.OpFlush:
		resp = d.OnFlush()
	case ocsd.OpReset:
		resp = d.OnReset()
	default:
		err = ocsd.ErrInvalidParamVal
		resp = ocsd.RespFatalInvalidOp
	}
	return ocsd.DataErrFromResp(resp, err)
}

// TracePacketData is the explicit packet data entrypoint used by split interfaces.
func (d *PktDecode) TracePacketData(indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	return d.PacketDataIn(ocsd.OpData, indexSOP, pktIn)
}

// TracePacketEOT forwards an EOT control operation through the legacy multiplexer.
func (d *PktDecode) TracePacketEOT() error {
	return d.PacketDataIn(ocsd.OpEOT, 0, nil)
}

// TracePacketFlush forwards a flush control operation through the legacy multiplexer.
func (d *PktDecode) TracePacketFlush() error {
	return d.PacketDataIn(ocsd.OpFlush, 0, nil)
}

// TracePacketReset forwards a reset control operation through the legacy multiplexer.
func (d *PktDecode) TracePacketReset(indexSOP ocsd.TrcIndex) error {
	return d.PacketDataIn(ocsd.OpReset, indexSOP, nil)
}

func (d *PktDecode) ProcessPacket() ocsd.DatapathResp {
	var resp ocsd.DatapathResp
	for fn := d.currentStateFn(); fn != nil; {
		next, loopResp, done := fn()
		resp = loopResp
		if done {
			return resp
		}
		fn = next
	}
	return ocsd.RespCont
}

func (d *PktDecode) currentStateFn() stateFn {
	switch d.currState {
	case dcdNoSync:
		return d.stateNoSync
	case dcdWaitSync:
		return d.stateWaitSync
	case dcdDecodePkts:
		return d.stateDecodePkts
	default:
		return nil
	}
}

func (d *PktDecode) stateNoSync() (stateFn, ocsd.DatapathResp, bool) {
	next, resp, done := d.handleNoSync()
	d.currState = next
	return d.currentStateFn(), resp, done
}

func (d *PktDecode) stateWaitSync() (stateFn, ocsd.DatapathResp, bool) {
	next, resp, done := d.handleWaitSync()
	d.currState = next
	return d.currentStateFn(), resp, done
}

func (d *PktDecode) stateDecodePkts() (stateFn, ocsd.DatapathResp, bool) {
	next, resp, done := d.handleDecodePkts()
	d.currState = next
	return d.currentStateFn(), resp, done
}

func (d *PktDecode) handleNoSync() (decoderState, ocsd.DatapathResp, bool) {
	d.outputElem.SetType(ocsd.GenElemNoSync)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncInfo(d.unsyncInfo))
	resp := ocsd.DataRespFromErr(d.OutputTraceElement(d.csID, &d.outputElem))
	return dcdWaitSync, resp, false // continue to waitSync
}

func (d *PktDecode) handleWaitSync() (decoderState, ocsd.DatapathResp, bool) {
	if d.CurrPacketIn.Type == PktAsync {
		return dcdDecodePkts, ocsd.RespCont, true
	}
	return dcdWaitSync, ocsd.RespCont, true
}

func (d *PktDecode) handleDecodePkts() (decoderState, ocsd.DatapathResp, bool) {
	return dcdDecodePkts, d.decodePacket(), true
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	resp := ocsd.DataRespFromErr(d.OutputTraceElement(d.csID, &d.outputElem))
	return resp
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	// d.resetDecoder() // C++ has it commented out
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	// don't currently save unsent packets so nothing to flush
	return ocsd.RespCont
}

func (d *PktDecode) TraceID() uint8 {
	return d.csID
}

func (d *PktDecode) configureDecoder() {
	d.csID = 0

	// base decoder state - ITM does not use memory or instruction decode.
	d.unsyncInfo = ocsd.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *PktDecode) resetDecoder() {
	d.outputElem.Init()
	d.currState = dcdNoSync
	d.pendingElements = d.pendingElements[:0]

	d.localTSCount = 0
	d.globalTS = 0
	d.stimPage = 0
	d.needGTS2 = true
	d.prevOverflow = false
	d.gtsFreqChange = false
}

// NextElement returns the next queued trace element or EOF if none available.
func (d *PktDecode) NextElement() (ocsd.TrcIndex, uint8, ocsd.TraceElement, error) {
	if len(d.pendingElements) == 0 {
		return 0, 0, ocsd.TraceElement{}, io.EOF
	}
	e := d.pendingElements[0]
	d.pendingElements = d.pendingElements[1:]
	if d.traceElemOut != nil {
		err := d.traceElemOut.TraceElemIn(e.index, e.traceID, &e.elem)
		if ocsd.IsDataContErr(err) {
			return e.index, e.traceID, e.elem, nil
		}
		if ocsd.IsDataWaitErr(err) {
			d.putBackElement(e.index, e.traceID, e.elem)
			return 0, 0, ocsd.TraceElement{}, ocsd.ErrWait
		}
		if err != nil {
			return 0, 0, ocsd.TraceElement{}, err
		}
	}
	return e.index, e.traceID, e.elem, nil
}

// Next returns one decoded trace element at a time for pull-based consumers.
func (d *PktDecode) Next() (*ocsd.TraceElement, error) {
	idx, traceID, elem, err := d.NextElement()
	if err != nil {
		return nil, err
	}
	e := elem
	e.Index = idx
	e.TraceID = traceID
	return &e, nil
}

// SetTraceElemOut attaches a transitional push sink for compatibility wiring.
func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) {
	d.traceElemOut = out
}

// putBackElement unreads an element to the front of the pending queue.
func (d *PktDecode) putBackElement(index ocsd.TrcIndex, traceID uint8, elem ocsd.TraceElement) {
	e := traceElemEvent{index, traceID, elem}
	d.pendingElements = append([]traceElemEvent{e}, d.pendingElements...)
}

func cloneQueuedElem(elem *ocsd.TraceElement) ocsd.TraceElement {
	clone := *elem
	if elem.PtrExtendedData != nil {
		clone.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return clone
}

func (d *PktDecode) decodePacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	globalTSLowMask := []uint64{
		0x00000007F, // [ 6:0]
		0x000003FFF, // [13:0]
		0x0001FFFFF, // [20:0]
		0x003FFFFFF, // [25:0]
	}
	globalTSHiMask := ^globalTSLowMask[3]

	sendPacket := false
	srcID := d.CurrPacketIn.SrcID

	localTSTCTypes := []ocsd.SWTItmType{
		ocsd.TSSync,
		ocsd.TSDelay,
		ocsd.TSPKTDelay,
		ocsd.TSPKTTSDelay,
	}

	d.itmInfo = ocsd.SWTItmInfo{}

	switch d.CurrPacketIn.Type {
	case PktIncompleteEOT:
		return resp
	case PktBadSequence, PktReserved:
		resp = ocsd.RespFatalInvalidData
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return resp
	}

	switch d.CurrPacketIn.Type {
	case PktNotSync:
		d.resetDecoder()

	case PktAsync:
		// do nothing

	case PktDWT:
		d.itmInfo.PktType = ocsd.DWTPayload
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case PktSWIT:
		d.itmInfo.PktType = ocsd.SWITPayload
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value
		srcID = (srcID & 0x1F) | (d.stimPage << 5)
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case PktExtension:
		if (srcID&0x80) == 0 && (srcID&0x1F) == 2 {
			d.stimPage = uint8(d.CurrPacketIn.Value)
		}

	case PktOverflow:
		d.localTSCount = 0
		d.prevOverflow = true

	case PktTSGlobal1:
		if !d.needGTS2 {
			d.needGTS2 = (srcID & 0x2) != 0
		}
		if !d.gtsFreqChange {
			d.gtsFreqChange = (srcID & 0x1) != 0
		}

		d.globalTS &= ^globalTSLowMask[d.CurrPacketIn.ValSz-1]
		d.globalTS |= uint64(d.CurrPacketIn.Value)

		if !d.needGTS2 {
			d.itmInfo.PktType = ocsd.TSGlobal
			d.outputElem.SetTS(d.globalTS, d.gtsFreqChange)
			d.gtsFreqChange = false
			sendPacket = true
		}

	case PktTSGlobal2:
		d.itmInfo.PktType = ocsd.TSGlobal
		d.globalTS &= ^globalTSHiMask
		d.globalTS |= (d.CurrPacketIn.ExtValue() << 26)
		d.outputElem.SetTS(d.globalTS, d.gtsFreqChange)
		d.gtsFreqChange = false
		d.needGTS2 = false
		sendPacket = true

	case PktTSLocal:
		d.itmInfo.PktType = localTSTCTypes[srcID&0x3]
		d.itmInfo.PayloadSize = d.CurrPacketIn.ValSz
		d.itmInfo.Value = d.CurrPacketIn.Value

		prescale := uint64(1)
		if d.Config != nil {
			prescale = uint64(d.Config.TSPrescaleValue())
		}
		d.localTSCount += uint64(d.itmInfo.Value) * prescale
		d.outputElem.SetTS(d.localTSCount, false)
		sendPacket = true
	}

	if sendPacket {
		if d.prevOverflow {
			d.itmInfo.Overflow = 1
			d.prevOverflow = false
		}
		d.outputElem.SetType(ocsd.GenElemITMTrace)
		d.outputElem.SetSWTITMInfo(d.itmInfo)
		resp = ocsd.DataRespFromErr(d.OutputTraceElement(d.csID, &d.outputElem))
	}

	return resp
}
