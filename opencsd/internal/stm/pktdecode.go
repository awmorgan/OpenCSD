package stm

import (
	"encoding/binary"
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

type PktDecode struct {
	Name         string
	TraceElemOut ocsd.GenElemProcessor
	MemAccess    common.TargetMemAccess
	InstrDecode  common.InstrDecode
	IndexCurrPkt ocsd.TrcIndex
	Config       *Config
	CurrPacketIn *Packet

	currState  decoderState
	unsyncInfo ocsd.UnsyncInfo

	swtPacketInfo ocsd.SWTInfo

	payloadBuffer     []byte
	payloadSize       int
	payloadUsed       int
	payloadOddNibble  bool
	numPktCorrelation int

	csID uint8

	decodePass1 bool
	outputElem  ocsd.TraceElement

	// Pull-iterator fields
	pendingElements []traceElemEvent
	collectElements bool
}

func (d *PktDecode) ApplyFlags(flags uint32) error { return nil }

// NewPktDecode creates a new STM packet decoder.
func NewPktDecode(cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: STM config cannot be nil", ocsd.ErrInvalidParamVal)
	}

	instIDNum := int(cfg.TraceID())
	d := &PktDecode{
		Name: fmt.Sprintf("DCD_STM_%d", instIDNum),
	}
	d.configureDecoder()
	if err := d.SetProtocolConfig(cfg); err != nil {
		return nil, err
	}
	return d, nil
}

// OutputTraceElement sends an element to the downstream consumer using IndexCurrPkt (or queues if in collect mode).
func (d *PktDecode) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error {
	if d.collectElements {
		e := traceElemEvent{d.IndexCurrPkt, traceID, *elem}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	if d.TraceElemOut == nil {
		return ocsd.ErrNotInit
	}
	err := d.TraceElemOut.TraceElemIn(d.IndexCurrPkt, traceID, elem)
	if ocsd.IsDataContErr(err) {
		return nil
	}
	if ocsd.IsDataWaitErr(err) {
		return ocsd.ErrWait
	}
	return err
}

// OutputTraceElementIdx sends an element to the downstream consumer at an explicit index.
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	if d.TraceElemOut == nil {
		return ocsd.ErrNotInit
	}
	err := d.TraceElemOut.TraceElemIn(idx, traceID, elem)
	if ocsd.IsDataContErr(err) {
		return nil
	}
	if ocsd.IsDataWaitErr(err) {
		return ocsd.ErrWait
	}
	return err
}

// AccessMemory reads target memory via the attached TargetMemAccess interface.
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

// InvalidateMemAccCache invalidates the memory access cache for the given trace ID.
func (d *PktDecode) InvalidateMemAccCache(traceID uint8) error {
	if d.MemAccess != nil {
		d.MemAccess.InvalidateMemAccCache(traceID)
		return nil
	}
	return ocsd.ErrDcdInterfaceUnused
}

// SetProtocolConfig sets the STM hardware configuration.
func (d *PktDecode) SetProtocolConfig(config *Config) error {
	d.Config = config
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
			// Drain queued elements
			if ocsd.DataRespIsCont(resp) {
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
	d.decodePass1 = true

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
	resp, done := d.decodePacket()
	return dcdDecodePkts, resp, done
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	resp := ocsd.DataRespFromErr(d.OutputTraceElement(d.csID, &d.outputElem))
	return resp
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	d.resetDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (d *PktDecode) TraceID() uint8 {
	return d.csID
}

func (d *PktDecode) configureDecoder() {
	d.numPktCorrelation = 1
	d.csID = 0

	d.unsyncInfo = ocsd.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *PktDecode) resetDecoder() {
	d.currState = dcdNoSync
	d.payloadSize = 0
	d.payloadUsed = 0
	d.payloadOddNibble = false
	d.outputElem.Init()
	d.swtPacketInfo = ocsd.SWTInfo{}
	d.pendingElements = d.pendingElements[:0]
	d.resetPayloadBuffer()
}

func (d *PktDecode) resetPayloadBuffer() {
	d.payloadBuffer = make([]byte, d.numPktCorrelation*8)
}

// NextElement returns the next queued trace element or EOF if none available.
func (d *PktDecode) NextElement() (ocsd.TrcIndex, uint8, ocsd.TraceElement, error) {
	if len(d.pendingElements) == 0 {
		return 0, 0, ocsd.TraceElement{}, io.EOF
	}
	e := d.pendingElements[0]
	d.pendingElements = d.pendingElements[1:]
	if d.TraceElemOut != nil {
		err := d.TraceElemOut.TraceElemIn(e.index, e.traceID, &e.elem)
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

// putBackElement unreads an element to the front of the pending queue.
func (d *PktDecode) putBackElement(index ocsd.TrcIndex, traceID uint8, elem ocsd.TraceElement) {
	e := traceElemEvent{index, traceID, elem}
	d.pendingElements = append([]traceElemEvent{e}, d.pendingElements...)
}

func (d *PktDecode) decodePacket() (resp ocsd.DatapathResp, done bool) {
	resp = ocsd.RespCont
	sendPacket := false
	done = true
	d.outputElem.SetType(ocsd.GenElemSWTrace)
	d.clearSWTPerPcktInfo()

	switch d.CurrPacketIn.Type {
	case PktIncompleteEOT:
		return resp, done
	case PktBadSequence, PktReserved:
		resp = ocsd.RespFatalInvalidData
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return resp, done
	}

	switch d.CurrPacketIn.Type {
	case PktNotSync:
		d.resetDecoder()
	case PktVersion:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
	case PktAsync:
		// no action required
	case PktNull:
		if d.CurrPacketIn.IsTSPkt() {
			sendPacket = true
		}
	case PktFreq:
		d.swtPacketInfo.SetFrequency(true)
		sendPacket = d.updatePayload()
	case PktTrig:
		d.swtPacketInfo.SetTriggerEvent(true)
		sendPacket = d.updatePayload()
	case PktGErr:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetGlobalErr(true)
		d.swtPacketInfo.SetIDValid(false)
		sendPacket = d.updatePayload()
	case PktMErr:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetMasterErr(true)
		sendPacket = d.updatePayload()
	case PktM8:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.SetIDValid(true)
	case PktC8, PktC16:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
	case PktFlag:
		d.swtPacketInfo.SetMarkerPacket(true)
		sendPacket = true
	case PktD4, PktD8, PktD16, PktD32, PktD64:
		sendPacket = d.updatePayload()
	}

	if sendPacket {
		if d.CurrPacketIn.IsTSPkt() {
			d.outputElem.SetTS(d.CurrPacketIn.Timestamp, true)
			d.swtPacketInfo.SetHasTimestamp(true)
		}
		d.outputElem.SetSWTInfo(d.swtPacketInfo)
		resp = ocsd.DataRespFromErr(d.OutputTraceElement(d.csID, &d.outputElem))
	}

	return resp, done
}

func (d *PktDecode) clearSWTPerPcktInfo() {
	d.swtPacketInfo.FlagBits &= ocsd.SwtIDValidMask
}

func (d *PktDecode) updatePayload() bool {
	d.swtPacketInfo.SetPayloadNumPackets(1)

	switch d.CurrPacketIn.Type {
	case PktD4:
		d.swtPacketInfo.SetPayloadPktBitsize(4)
		d.payloadBuffer[0] = d.CurrPacketIn.Payload.D8
	case PktD8, PktTrig, PktGErr, PktMErr:
		d.swtPacketInfo.SetPayloadPktBitsize(8)
		d.payloadBuffer[0] = d.CurrPacketIn.Payload.D8
	case PktD16:
		d.swtPacketInfo.SetPayloadPktBitsize(16)
		binary.LittleEndian.PutUint16(d.payloadBuffer, d.CurrPacketIn.Payload.D16)
	case PktD32, PktFreq:
		d.swtPacketInfo.SetPayloadPktBitsize(32)
		binary.LittleEndian.PutUint32(d.payloadBuffer, d.CurrPacketIn.Payload.D32)
	case PktD64:
		d.swtPacketInfo.SetPayloadPktBitsize(64)
		binary.LittleEndian.PutUint64(d.payloadBuffer, d.CurrPacketIn.Payload.D64)
	}

	d.outputElem.SetExtendedDataPtr(d.payloadBuffer)
	if d.CurrPacketIn.IsMarkerPkt() {
		d.swtPacketInfo.SetMarkerPacket(true)
	}
	return true
}
