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

type stateFn func() (stateFn, error, bool)

type PktDecode struct {
	Name         string
	traceElemOut ocsd.GenElemProcessor
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

	pendingElements []traceElemEvent

	// Source is the pull-based packet reader injected at construction time.
	// May be nil when the push-based Write path is used instead.
	Source ocsd.PacketReader[Packet]
}

func (d *PktDecode) ApplyFlags(flags uint32) error { return nil }

// SetTraceElemOut wires an optional legacy push-style sink.
func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) {
	d.traceElemOut = out
}

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

// OutputTraceElement queues an element for pull-based consumption using IndexCurrPkt.
func (d *PktDecode) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error {
	e := traceElemEvent{d.IndexCurrPkt, traceID, cloneQueuedElem(elem)}
	d.pendingElements = append(d.pendingElements, e)
	return nil
}

// OutputTraceElementIdx queues an element at an explicit index.
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	e := traceElemEvent{idx, traceID, cloneQueuedElem(elem)}
	d.pendingElements = append(d.pendingElements, e)
	return nil
}

func cloneQueuedElem(elem *ocsd.TraceElement) ocsd.TraceElement {
	clone := *elem
	if elem.PtrExtendedData != nil {
		clone.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return clone
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

// Write is the explicit packet data entrypoint used by split interfaces.
func (d *PktDecode) Write(indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	if pktIn == nil {
		return ocsd.ErrInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = indexSOP
	err := d.ProcessPacket()
	if err == nil && d.traceElemOut != nil {
		for {
			_, _, _, nextErr := d.NextElement()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				return nextErr
			}
		}
	}
	return err
}

// Close forwards an EOT control operation through the legacy multiplexer.
func (d *PktDecode) Close() error {
	err := d.OnEOT()
	if err == nil && d.traceElemOut != nil {
		for {
			_, _, _, nextErr := d.NextElement()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				return nextErr
			}
		}
	}
	return err
}

// Flush forwards a flush control operation through the legacy multiplexer.
func (d *PktDecode) Flush() error {
	return d.OnFlush()
}

// Reset forwards a reset control operation through the legacy multiplexer.
func (d *PktDecode) Reset(indexSOP ocsd.TrcIndex) error {
	_ = indexSOP
	return d.OnReset()
}

func (d *PktDecode) ProcessPacket() error {
	d.decodePass1 = true

	for fn := d.currentStateFn(); fn != nil; {
		next, err, done := fn()
		if done {
			return err
		}
		fn = next
	}
	return nil
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

func (d *PktDecode) stateNoSync() (stateFn, error, bool) {
	next, err, done := d.handleNoSync()
	d.currState = next
	return d.currentStateFn(), err, done
}

func (d *PktDecode) stateWaitSync() (stateFn, error, bool) {
	next, err, done := d.handleWaitSync()
	d.currState = next
	return d.currentStateFn(), err, done
}

func (d *PktDecode) stateDecodePkts() (stateFn, error, bool) {
	next, err, done := d.handleDecodePkts()
	d.currState = next
	return d.currentStateFn(), err, done
}

func (d *PktDecode) handleNoSync() (decoderState, error, bool) {
	d.outputElem.SetType(ocsd.GenElemNoSync)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncInfo(d.unsyncInfo))
	err := d.OutputTraceElement(d.csID, &d.outputElem)
	return dcdWaitSync, err, false // continue to waitSync
}

func (d *PktDecode) handleWaitSync() (decoderState, error, bool) {
	if d.CurrPacketIn.Type == PktAsync {
		return dcdDecodePkts, nil, true
	}
	return dcdWaitSync, nil, true
}

func (d *PktDecode) handleDecodePkts() (decoderState, error, bool) {
	err, done := d.decodePacket()
	return dcdDecodePkts, err, done
}

func (d *PktDecode) OnEOT() error {
	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	return d.OutputTraceElement(d.csID, &d.outputElem)
}

func (d *PktDecode) OnReset() error {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	d.resetDecoder()
	return nil
}

func (d *PktDecode) OnFlush() error {
	return nil
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
// When a pull-based Source is set and no push sink is wired, it fetches the
// next packet from Source, decodes it, and returns the first resulting element.
func (d *PktDecode) NextElement() (ocsd.TrcIndex, uint8, ocsd.TraceElement, error) {
	for len(d.pendingElements) == 0 && d.Source != nil && d.traceElemOut == nil {
		pkt, err := d.Source.NextPacket()
		if errors.Is(err, io.EOF) {
			d.Source = nil
			_ = d.Close()
			break
		}
		if err != nil {
			d.Source = nil
			return 0, 0, ocsd.TraceElement{}, err
		}
		if wErr := d.Write(0, &pkt); wErr != nil {
			return 0, 0, ocsd.TraceElement{}, wErr
		}
	}
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

// putBackElement unreads an element to the front of the pending queue.
func (d *PktDecode) putBackElement(index ocsd.TrcIndex, traceID uint8, elem ocsd.TraceElement) {
	e := traceElemEvent{index, traceID, elem}
	d.pendingElements = append([]traceElemEvent{e}, d.pendingElements...)
}

func (d *PktDecode) decodePacket() (err error, done bool) {
	sendPacket := false
	done = true
	d.outputElem.SetType(ocsd.GenElemSWTrace)
	d.clearSWTPerPcktInfo()

	switch d.CurrPacketIn.Type {
	case PktIncompleteEOT:
		return nil, done
	case PktBadSequence, PktReserved:
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.ErrPktInterpFail, done
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
		d.swtPacketInfo.Frequency = true
		sendPacket = d.updatePayload()
	case PktTrig:
		d.swtPacketInfo.TriggerEvent = true
		sendPacket = d.updatePayload()
	case PktGErr:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.GlobalErr = true
		d.swtPacketInfo.IDValid = false
		sendPacket = d.updatePayload()
	case PktMErr:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.MasterErr = true
		sendPacket = d.updatePayload()
	case PktM8:
		d.swtPacketInfo.MasterID = uint16(d.CurrPacketIn.Master)
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
		d.swtPacketInfo.IDValid = true
	case PktC8, PktC16:
		d.swtPacketInfo.ChannelID = uint16(d.CurrPacketIn.Channel)
	case PktFlag:
		d.swtPacketInfo.MarkerPacket = true
		sendPacket = true
	case PktD4, PktD8, PktD16, PktD32, PktD64:
		sendPacket = d.updatePayload()
	}

	if sendPacket {
		if d.CurrPacketIn.IsTSPkt() {
			d.outputElem.SetTS(d.CurrPacketIn.Timestamp, true)
			d.swtPacketInfo.HasTimestamp = true
		}
		d.outputElem.SetSWTInfo(d.swtPacketInfo)
		return d.OutputTraceElement(d.csID, &d.outputElem), done
	}

	return nil, done
}

func (d *PktDecode) clearSWTPerPcktInfo() {
	d.swtPacketInfo = ocsd.SWTInfo{
		MasterID:  d.swtPacketInfo.MasterID,
		ChannelID: d.swtPacketInfo.ChannelID,
		IDValid:   d.swtPacketInfo.IDValid,
	}
}

func (d *PktDecode) updatePayload() bool {
	d.swtPacketInfo.PayloadNumPackets = 1

	switch d.CurrPacketIn.Type {
	case PktD4:
		d.swtPacketInfo.PayloadPktBitsize = 4
		d.payloadBuffer[0] = d.CurrPacketIn.Payload.D8
	case PktD8, PktTrig, PktGErr, PktMErr:
		d.swtPacketInfo.PayloadPktBitsize = 8
		d.payloadBuffer[0] = d.CurrPacketIn.Payload.D8
	case PktD16:
		d.swtPacketInfo.PayloadPktBitsize = 16
		binary.LittleEndian.PutUint16(d.payloadBuffer, d.CurrPacketIn.Payload.D16)
	case PktD32, PktFreq:
		d.swtPacketInfo.PayloadPktBitsize = 32
		binary.LittleEndian.PutUint32(d.payloadBuffer, d.CurrPacketIn.Payload.D32)
	case PktD64:
		d.swtPacketInfo.PayloadPktBitsize = 64
		binary.LittleEndian.PutUint64(d.payloadBuffer, d.CurrPacketIn.Payload.D64)
	}

	d.outputElem.SetExtendedDataPtr(d.payloadBuffer)
	if d.CurrPacketIn.IsMarkerPkt() {
		d.swtPacketInfo.MarkerPacket = true
	}
	return true
}
