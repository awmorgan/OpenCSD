package itm

import (
	"errors"
	"fmt"
	"io"
	"iter"

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

// PktDecode decodes ITM packets into generic ITM-SW trace packets.
type PktDecode struct {
	Name         string
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

	// Source is the pull-based packet reader injected at construction time.
	// May be nil when the push-based Write path is used instead.
	Source ocsd.PacketReader[Packet]
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
	e := traceElemEvent{d.IndexCurrPkt, traceID, cloneQueuedElem(elem)}
	d.pendingElements = append(d.pendingElements, e)
	return nil
}

// OutputTraceElementIdx sends an element at an explicit index.
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	e := traceElemEvent{idx, traceID, cloneQueuedElem(elem)}
	d.pendingElements = append(d.pendingElements, e)
	return nil
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

// Write is the explicit packet data entrypoint used by split interfaces.
func (d *PktDecode) Write(indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	if pktIn == nil {
		return ocsd.ErrInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = indexSOP
	return d.ProcessPacket()
}

// Close forwards an EOT control operation through the legacy multiplexer.
func (d *PktDecode) Close() error {
	return d.OnEOT()
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
	return dcdDecodePkts, d.decodePacket(), true
}

func (d *PktDecode) OnEOT() error {
	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	return d.OutputTraceElement(d.csID, &d.outputElem)
}

func (d *PktDecode) OnReset() error {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	// d.resetDecoder() // C++ has it commented out
	return nil
}

func (d *PktDecode) OnFlush() error {
	// don't currently save unsent packets so nothing to flush
	return nil
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
// When a pull-based Source is set and no push sink is wired, it fetches the
// next packet from Source, decodes it, and returns the first resulting element.
func (d *PktDecode) NextElement() (ocsd.TrcIndex, uint8, ocsd.TraceElement, error) {
	for len(d.pendingElements) == 0 && d.Source != nil {
		pkt, err := d.Source.NextPacket()
		if errors.Is(err, io.EOF) {
			d.Source = nil
			_ = d.Close()
			break
		}
		if err != nil {
			if !errors.Is(err, ocsd.ErrWait) {
				d.Source = nil
			}
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

// Elements provides a standard Go 1.23 iterator over the trace elements.
// It wraps the legacy pull-based Next() method.
func (d *PktDecode) Elements() iter.Seq2[*ocsd.TraceElement, error] {
	return func(yield func(*ocsd.TraceElement, error) bool) {
		for {
			elem, err := d.Next()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					yield(nil, err)
				}
				return
			}
			if !yield(elem, nil) {
				return
			}
		}
	}
}

func cloneQueuedElem(elem *ocsd.TraceElement) ocsd.TraceElement {
	clone := *elem
	if elem.PtrExtendedData != nil {
		clone.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return clone
}

func (d *PktDecode) decodePacket() error {
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
		return nil
	case PktBadSequence, PktReserved:
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.ErrPktInterpFail
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
		return d.OutputTraceElement(d.csID, &d.outputElem)
	}

	return nil
}
