package etmv3

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// ElementCallback is called for each output trace element when an output sink is set.
type ElementCallback func(*ocsd.TraceElement) error

type decoderState int

const (
	noSync decoderState = iota
	waitAsync
	waitISync
	decodePkts
	sendPkts
)

var isyncOnReasonMap = [...]ocsd.TraceOnReason{
	ocsd.TraceOnNormal,
	ocsd.TraceOnNormal,
	ocsd.TraceOnOverflow,
	ocsd.TraceOnExDebug,
}

// PktDecode implements the ETMv3 packet decoder converting packets to generic TraceElements
// Ported from trc_pkt_decode_etmv3.cpp
// Speculative decoding uses a tiny fixed-size element buffer for per-packet output staging.
type traceElemEvent struct {
	index   ocsd.TrcIndex
	traceID uint8
	elem    ocsd.TraceElement
}

type PktDecode struct {
	Name         string
	MemAccess    common.TargetMemAccess
	InstrDecode  common.InstrDecode
	IndexCurrPkt ocsd.TrcIndex
	Config       *Config
	CurrPacketIn *Packet

	currState  decoderState
	unsyncInfo ocsd.UnsyncInfo

	codeFollower *common.CodeFollower

	iAddr       uint64
	NeedAddr    bool
	SentUnknown bool
	waitISync   bool

	peContext *ocsd.PEContext

	outBuf    [16]traceElemEvent
	outCount  int
	pendBuf   [16]traceElemEvent
	pendCount int

	pendingNacc    bool
	pendingNaccIdx ocsd.TrcIndex
	pendingNaccAdr uint64
	pendingNaccMem ocsd.MemSpaceAcc

	csID            uint8
	pendingElements []traceElemEvent

	// NEW: Callback for zero-allocation iterator
	outCallback func(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) bool

	// Internal source.
	Source ocsd.PacketReader[Packet]
}

func (d *PktDecode) ApplyFlags(flags uint32) error { return nil }

// NewPktDecode creates a new ETMv3 trace decoder.
func NewPktDecode(cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode, source ocsd.PacketReader[Packet]) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETMv3 config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if mem == nil {
		return nil, fmt.Errorf("%w: ETMv3 mem access cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if instr == nil {
		return nil, fmt.Errorf("%w: ETMv3 instruction decoder cannot be nil", ocsd.ErrInvalidParamVal)
	}

	instID := int(cfg.TraceID())
	codeFollower, err := common.NewCodeFollowerWithInterfaces(mem, instr)
	if err != nil {
		return nil, err
	}

	d := &PktDecode{
		Name:         fmt.Sprintf("DCD_ETMV3_%d", instID),
		MemAccess:    mem,
		InstrDecode:  instr,
		peContext:    &ocsd.PEContext{},
		codeFollower: codeFollower,
	}
	// wire-in optional dependencies
	d.Source = source
	d.configureDecoder()

	d.Config = cfg
	d.csID = d.Config.TraceID()

	if d.Config.TraceMode() != TMInstrOnly {
		err := ocsd.ErrHWCfgUnsupp
		return nil, fmt.Errorf("%w: ETMv3 trace decoder: data trace decode not yet supported", err)
	}

	archProfile := ocsd.ArchProfile{
		Arch:    d.Config.ArchVer,
		Profile: d.Config.CoreProf,
	}

	d.codeFollower.Arch = archProfile
	d.codeFollower.InstrInfo.PeType = archProfile
	d.codeFollower.TraceID = d.csID

	return d, nil
}

// OutputTraceElement sends an element using IndexCurrPkt.
func (d *PktDecode) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error {
	if d == nil || elem == nil {
		return nil
	}
	return d.OutputTraceElementIdx(d.IndexCurrPkt, traceID, elem)
}

// OutputTraceElementIdx sends an element at an explicit index.
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	if d == nil || elem == nil {
		return nil
	}
	elem.Index = idx
	elem.TraceID = traceID

	// NEW: Route to callback if it is wired up
	if d.outCallback != nil {
		if !d.outCallback(idx, traceID, elem) {
			return ocsd.ErrWait
		}
		return nil
	}

	// FALLBACK: Legacy slice append behavior
	d.pendingElements = append(d.pendingElements, traceElemEvent{
		index:   idx,
		traceID: traceID,
		elem:    cloneQueuedElem(elem),
	})
	return nil
}

// SetOutCallback wires a direct output sink, bypassing internal buffers.
func (d *PktDecode) SetOutCallback(cb func(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) bool) {
	d.outCallback = cb
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

// Close handles end-of-trace control.
func (d *PktDecode) Close() error {
	return d.OnEOT()
}

// Flush handles flush control.
func (d *PktDecode) Flush() error {
	return d.OnFlush()
}

// Reset handles reset control.
func (d *PktDecode) Reset(indexSOP ocsd.TrcIndex) error {
	_ = indexSOP
	d.OnReset()
	return nil
}

// NextElement returns the next queued trace element or pulls from Source.
func (d *PktDecode) NextElement() (ocsd.TrcIndex, uint8, ocsd.TraceElement, error) {
	for len(d.pendingElements) == 0 {
		err := d.processNext()
		if err != nil {
			return 0, 0, ocsd.TraceElement{}, err
		}
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

// processNext pulls the next packet from the bound source and immediately decodes it into the output sink.
func (d *PktDecode) processNext() error {
	if d.Source == nil {
		return io.EOF
	}

	pkt, err := d.Source.NextPacket()
	if err != nil {
		if errors.Is(err, io.EOF) {
			d.Source = nil
			_ = d.Close()
			d.flushOutputElements()
			return nil
		}
		return err
	}

	d.CurrPacketIn = &pkt
	d.IndexCurrPkt = pkt.Index

	err = d.processPacket()
	if err != nil {
		return err
	}

	d.flushOutputElements()

	return nil
}

func cloneQueuedElem(elem *ocsd.TraceElement) ocsd.TraceElement {
	if elem == nil {
		return ocsd.TraceElement{}
	}
	copyElem := *elem
	if len(elem.PtrExtendedData) > 0 {
		copyElem.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return copyElem
}

// Elements provides a standard Go 1.23 iterator over the trace elements.
// It directly drives the packet decoder and yields elements with zero queue allocation.
func (d *PktDecode) Elements() iter.Seq2[*ocsd.TraceElement, error] {
	return func(yield func(*ocsd.TraceElement, error) bool) {
		if d.Source == nil {
			return
		}

		yieldActive := true

		// Wire the callback directly to the iterator's yield function
		d.outCallback = func(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) bool {
			if !yieldActive {
				return false
			}
			e := cloneQueuedElem(elem)
			e.Index = idx
			e.TraceID = traceID
			yieldActive = yield(&e, nil)
			return yieldActive
		}

		defer func() {
			d.outCallback = nil
		}()

		// Drive the decode process
		for yieldActive {
			pkt, err := d.Source.NextPacket()
			if err != nil {
				if errors.Is(err, io.EOF) {
					d.Source = nil
					if closeErr := d.Close(); closeErr != nil {
						yield(nil, closeErr)
					}
					return
				}
				yield(nil, err)
				return
			}

			d.CurrPacketIn = &pkt
			d.IndexCurrPkt = pkt.Index

			if err := d.processPacket(); err != nil {
				if errors.Is(err, ocsd.ErrWait) {
					return
				}
				yield(nil, err)
				return
			}

			// This will trigger OutputTraceElementIdx, hit our callback, and yield
			d.flushOutputElements()
		}
	}
}

// putBackElement unreads an element to the front of the pending queue.
func (d *PktDecode) flushOutputElements() {
	for i := 0; i < d.outCount; i++ {
		queued := &d.outBuf[i]
		elem := cloneQueuedElem(&queued.elem)
		elem.TraceID = queued.traceID
		_ = d.OutputTraceElementIdx(queued.index, queued.traceID, &elem)
	}
	d.outCount = 0
}

func (d *PktDecode) configureDecoder() {
	d.csID = 0
	d.resetDecoder()
	d.unsyncInfo = ocsd.UnsyncInitDecoder
}

func (d *PktDecode) resetDecoder() {
	d.currState = noSync
	d.NeedAddr = true
	d.SentUnknown = false
	d.waitISync = false
	d.outCount = 0
	d.pendCount = 0
	d.pendingElements = d.pendingElements[:0]
	d.pendingNacc = false
	d.pendingNaccIdx = 0
	d.pendingNaccAdr = 0
	d.pendingNaccMem = ocsd.MemSpaceNone
}

func (d *PktDecode) nextDecodeState() decoderState {
	if d.waitISync {
		return waitISync
	}
	return decodePkts
}

func (d *PktDecode) OnReset() {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	d.resetDecoder()
}

func (d *PktDecode) OnFlush() error {
	if d.numOutElem() == 0 && d.pendCount == 0 && !d.pendingNacc {
		return nil
	}

	d.commitAllPendOutElem()
	err := d.emitPendingNacc()
	if err != nil {
		return err
	}

	d.flushOutputElements()
	d.currState = d.nextDecodeState()
	return nil
}

func (d *PktDecode) OnEOT() error {
	d.commitAllPendOutElem()
	err := d.emitPendingNacc()
	if err != nil {
		return err
	}

	elem, err := d.getNextOpElem()
	if err != nil {
		d.resetDecoder()
		return ocsd.ErrFail
	}
	elem.SetType(ocsd.GenElemEOTrace)
	elem.Payload.UnsyncEOTInfo = ocsd.UnsyncEOT
	d.commitAllPendOutElem()

	d.flushOutputElements()
	d.currState = decodePkts

	return nil
}

func (d *PktDecode) processPacket() error {
	if d.Config == nil {
		return ocsd.ErrNotInit
	}

	var err error
	for {
		var next decoderState
		var done bool
		switch d.currState {
		case noSync:
			next, err, done = d.handleNoSync()
		case waitAsync:
			next, err, done = d.handleWaitAsync()
		case waitISync:
			next, err, done = d.handleWaitISync()
		case decodePkts:
			next, err, done = d.handleDecodePkts()
		case sendPkts:
			next, err, done = d.handleSendPkts()
		default:
			d.resetDecoder()
			return ocsd.ErrFail
		}
		d.currState = next
		if done {
			return err
		}
	}
}

func (d *PktDecode) handleNoSync() (decoderState, error, bool) {
	err := d.sendUnsyncPacket()
	return waitAsync, err, false // continue to waitAsync
}

func (d *PktDecode) handleWaitAsync() (decoderState, error, bool) {
	if d.CurrPacketIn.Type == PktASync {
		return waitISync, nil, true
	}
	return waitAsync, nil, true
}

func (d *PktDecode) handleWaitISync() (decoderState, error, bool) {
	d.waitISync = true
	packetIn := d.CurrPacketIn
	if packetIn.Type == PktISync || packetIn.Type == PktISyncCycle {
		err := d.processISync(true)
		d.waitISync = false
		return d.nextSendOrDecodeState(), err, false
	}
	if d.preISyncValid(packetIn.Type) {
		next, err, done := d.handleDecodePkts()
		return next, err, done
	}
	return waitISync, nil, true
}

func (d *PktDecode) handleDecodePkts() (decoderState, error, bool) {
	err, done := d.decodePacket()
	next := d.nextSendOrDecodeState()
	return next, err, done
}

func (d *PktDecode) handleSendPkts() (decoderState, error, bool) {
	d.flushOutputElements()
	return d.nextDecodeState(), nil, true
}

// nextSendOrDecodeState returns sendPkts if there are elements to send, otherwise the next decode state.
func (d *PktDecode) nextSendOrDecodeState() decoderState {
	if d.outElemToSend() {
		return sendPkts
	}
	return d.nextDecodeState()
}

func (d *PktDecode) getNextOpElem() (*ocsd.TraceElement, error) {
	return d.nextOutElem(d.IndexCurrPkt), nil
}

func (d *PktDecode) getNextOpElemAt(index ocsd.TrcIndex) (*ocsd.TraceElement, error) {
	return d.nextOutElem(index), nil
}

func (d *PktDecode) queuePendingNacc(addr uint64, memSpace ocsd.MemSpaceAcc) {
	d.pendingNacc = true
	d.pendingNaccIdx = d.IndexCurrPkt
	d.pendingNaccAdr = addr
	d.pendingNaccMem = memSpace
}

func (d *PktDecode) clearPendingNacc() {
	d.pendingNacc = false
	d.pendingNaccIdx = 0
	d.pendingNaccAdr = 0
	d.pendingNaccMem = ocsd.MemSpaceNone
}

func (d *PktDecode) emitPendingNacc() error {
	if !d.pendingNacc {
		return nil
	}

	elem, err := d.getNextOpElemAt(d.pendingNaccIdx)
	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.ErrFail
	}

	elem.SetType(ocsd.GenElemAddrNacc)
	elem.StartAddr = ocsd.VAddr(d.pendingNaccAdr)
	elem.Payload.ExceptionNum = uint32(d.pendingNaccMem)
	d.clearPendingNacc()
	return nil
}

func (d *PktDecode) preISyncValid(pktType PktType) bool {
	if pktType == PktTimestamp || (d.Config.CycleAcc() && (pktType == PktCycleCount || pktType == PktPHdr)) {
		return true
	}
	return false
}

func (d *PktDecode) sendUnsyncPacket() error {
	elem, err := d.getNextOpElem()
	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.ErrFail
	}

	elem.SetType(ocsd.GenElemNoSync)
	elem.Payload.UnsyncEOTInfo = ocsd.UnsyncInfo(d.unsyncInfo)
	d.flushOutputElements()
	return nil
}

func (d *PktDecode) decodePacket() (err error, done bool) {
	done = false

	packetIn := d.CurrPacketIn
	if packetIn.Err != nil {
		switch packetIn.displayType() {
		case PktIncompleteEOT:
			return nil, true
		case PktBadSequence, PktBadTraceMode, PktReserved:
			d.unsyncInfo = ocsd.UnsyncBadPacket
			d.resetDecoder()
			return ocsd.ErrInvalidParamVal, true
		}
	}

	if packetIn.Type != PktBranchAddress {
		d.commitAllPendOutElem()
		err = d.emitPendingNacc()
		if err != nil {
			return err, true
		}
	}

	var elem *ocsd.TraceElement

	switch packetIn.Type {
	case PktNotSync:
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.ErrFail, true

	case PktIncompleteEOT, PktASync, PktIgnore:
		// ignore
	case PktCycleCount:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemCycleCount)
			elem.SetCycleCount(packetIn.CycleCount)
		}
	case PktTrigger:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemEvent)
			elem.Payload.TraceEvent.EvType = ocsd.EventTrigger
		}
	case PktBranchAddress:
		err = d.processBranchAddr()
	case PktISyncCycle, PktISync:
		err = d.processISync(false)
	case PktPHdr:
		err = d.processPHdr()
	case PktContextID:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemPeContext)
			d.peContext.ContextID = packetIn.Context.CtxtID
			d.peContext.CtxtIDValid = true
			elem.Context = *d.peContext
		}
	case PktVMID:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemPeContext)
			d.peContext.VMID = uint32(packetIn.Context.VMID)
			d.peContext.VMIDValid = true
			elem.Context = *d.peContext
		}
	case PktExceptionEntry:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemException)
			elem.ExceptionDataMarker = true
		}
	case PktExceptionExit:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemExceptionRet)
			d.pendExceptionReturn()
		}
	case PktTimestamp:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemTimestamp)
			elem.Timestamp = packetIn.Timestamp
		}
	case PktStoreFail, PktOOOData, PktOOOAddrPlc, PktNormData, PktDataSuppressed, PktValNotTraced, PktBadTraceMode:
		err = ocsd.ErrInvalidParamVal
	case PktBadSequence:
		err = ocsd.ErrBadPacketSeq
	case PktReserved:
		fallthrough
	default:
		err = ocsd.ErrInvalidParamVal
	}

	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return err, true
	}

	if d.outElemToSend() {
		// caller (handleDecodePkts) will compute next state via nextSendOrDecodeState
	}
	done = !d.outElemToSend()
	return nil, done
}

func (d *PktDecode) processISync(firstSync bool) error {
	packetIn := d.CurrPacketIn
	ctxtUpdate := packetIn.Context.UpdatedC || packetIn.Context.UpdatedV || packetIn.Context.Updated

	elem, err := d.getNextOpElem()
	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.ErrFail
	}

	if firstSync || packetIn.ISyncInfo.Reason != ocsd.ISyncPeriodic {
		elem.SetType(ocsd.GenElemTraceOn)
		if int(packetIn.ISyncInfo.Reason) < len(isyncOnReasonMap) {
			elem.Payload.TraceOnReason = isyncOnReasonMap[packetIn.ISyncInfo.Reason]
		}
		elem, err = d.getNextOpElem()
		if err != nil {
			d.unsyncInfo = ocsd.UnsyncBadPacket
			d.resetDecoder()
			return ocsd.ErrFail
		}
	}

	if ctxtUpdate || firstSync {
		if firstSync {
			d.peContext = &ocsd.PEContext{}
		}

		if packetIn.Context.UpdatedC {
			d.peContext.ContextID = packetIn.Context.CtxtID
			d.peContext.CtxtIDValid = true
		}
		if packetIn.Context.UpdatedV {
			d.peContext.VMID = uint32(packetIn.Context.VMID)
			d.peContext.VMIDValid = true
		}
		if packetIn.Context.Updated {
			el := ocsd.ELUnknown
			if packetIn.Context.CurrHyp {
				el = ocsd.EL2
			}
			sec := ocsd.SecSecure
			if packetIn.Context.CurrNS {
				sec = ocsd.SecNonsecure
			}
			d.peContext.ExceptionLevel = el
			d.peContext.ELValid = true
			d.peContext.SecurityLevel = sec
		}

		elem.SetType(ocsd.GenElemPeContext)
		elem.Context = *d.peContext
		elem.ISA = packetIn.CurrISA
		d.codeFollower.Isa = packetIn.CurrISA
		d.codeFollower.InstrInfo.ISA = packetIn.CurrISA

		if packetIn.ISyncInfo.HasCycleCount {
			elem.SetCycleCount(packetIn.CycleCount)
		}
	}

	if !packetIn.ISyncInfo.NoAddress {
		if packetIn.ISyncInfo.HasLSipAddr {
			d.iAddr = packetIn.Data.Addr
		} else {
			d.iAddr = packetIn.Addr
		}
		d.NeedAddr = false
		d.SentUnknown = false
	}

	if d.outElemToSend() {
		// caller will compute next state via nextSendOrDecodeState
	}

	return nil
}

func (d *PktDecode) atomCC(packetIn *Packet, atomsNum uint8, isCCPacket bool) uint32 {
	if !isCCPacket {
		return 0
	}
	switch packetIn.PHdrFmt {
	case 3:
		return packetIn.CycleCount
	case 2:
		if atomsNum > 1 {
			return 1
		}
		return 0
	case 1:
		return 1
	default:
		return 0
	}
}

func (d *PktDecode) remainCC(packetIn *Packet, atomsNum uint8, isCCPacket bool) uint32 {
	if !isCCPacket {
		return 0
	}
	switch packetIn.PHdrFmt {
	case 3:
		return packetIn.CycleCount
	case 2:
		if atomsNum > 1 {
			return 1
		}
		return 0
	case 1:
		return uint32(atomsNum)
	default:
		return 0
	}
}

func (d *PktDecode) processBranchAddr() error {
	packetIn := d.CurrPacketIn
	updatePEContext := false

	if packetIn.ExceptionCancel {
		d.cancelPendOutElem()
		d.clearPendingNacc()
	} else {
		d.commitAllPendOutElem()
		err := d.emitPendingNacc()
		if err != nil {
			return err
		}
	}

	d.iAddr = packetIn.Addr
	d.NeedAddr = false
	d.SentUnknown = false
	d.codeFollower.Isa = packetIn.CurrISA
	d.codeFollower.InstrInfo.ISA = packetIn.CurrISA

	if packetIn.Context.UpdatedC || packetIn.Context.UpdatedV || packetIn.Context.Updated {
		if packetIn.Context.UpdatedC && (!d.peContext.CtxtIDValid || d.peContext.ContextID != packetIn.Context.CtxtID) {
			d.peContext.ContextID = packetIn.Context.CtxtID
			d.peContext.CtxtIDValid = true
			updatePEContext = true
		}
		if packetIn.Context.UpdatedV && (!d.peContext.VMIDValid || d.peContext.VMID != uint32(packetIn.Context.VMID)) {
			d.peContext.VMID = uint32(packetIn.Context.VMID)
			d.peContext.VMIDValid = true
			updatePEContext = true
		}
		if packetIn.Context.Updated {
			sec := ocsd.SecSecure
			if packetIn.Context.CurrNS {
				sec = ocsd.SecNonsecure
			}
			if sec != d.peContext.SecurityLevel {
				d.peContext.SecurityLevel = sec
				updatePEContext = true
			}

			el := ocsd.ELUnknown
			if packetIn.Context.CurrHyp {
				el = ocsd.EL2
			}
			if !d.peContext.ELValid || el != d.peContext.ExceptionLevel {
				d.peContext.ExceptionLevel = el
				d.peContext.ELValid = true
				updatePEContext = true
			}
		}
	}

	if updatePEContext {
		elem, err := d.getNextOpElem()
		if err != nil {
			d.unsyncInfo = ocsd.UnsyncBadPacket
			d.resetDecoder()
			return ocsd.ErrFail
		}
		elem.SetType(ocsd.GenElemPeContext)
		elem.Context = *d.peContext
	}

	if packetIn.Exception.Present {
		if packetIn.Exception.Number != 0 {
			elem, err := d.getNextOpElem()
			if err != nil {
				d.unsyncInfo = ocsd.UnsyncBadPacket
				d.resetDecoder()
				return ocsd.ErrFail
			}
			elem.SetType(ocsd.GenElemException)
			elem.Payload.ExceptionNum = uint32(packetIn.Exception.Number)
		}
	}

	if d.outElemToSend() {
		// caller will compute next state via nextSendOrDecodeState
	}

	return nil
}

func (d *PktDecode) pendExceptionReturn() {
	pendElem := 1
	if d.Config.CoreProf != ocsd.ProfileCortexM {
		nElem := d.numOutElem()
		if nElem > 1 {
			if d.outElemType(nElem-2) == ocsd.GenElemInstrRange {
				pendElem = 2
			}
		}
	}
	d.pendLastNOutElem(pendElem)
}

// processPHdr uses the etmv3Atoms struct pattern natively in Go inline since it doesn't need external exposure.
func (d *PktDecode) processPHdr() error {
	packetIn := d.CurrPacketIn
	isa := packetIn.CurrISA

	// Mimicking etmv3Atoms behaviors
	atomsNum := packetIn.Atom.Num
	enBits := packetIn.Atom.EnBits

	isCCPacket := d.Config.CycleAcc()

	memSpace := ocsd.MemSpaceN
	if d.peContext.SecurityLevel == ocsd.SecSecure {
		memSpace = ocsd.MemSpaceS
	}
	var elem *ocsd.TraceElement
	var err error

	d.codeFollower.MemSpace = memSpace

	for {
		if d.NeedAddr {
			if !d.SentUnknown || d.Config.CycleAcc() {
				elem, err := d.getNextOpElem()
				if err != nil {
					d.unsyncInfo = ocsd.UnsyncBadPacket
					d.resetDecoder()
					return ocsd.ErrFail
				}
				if d.SentUnknown || atomsNum == 0 {
					elem.SetType(ocsd.GenElemCycleCount)
				} else {
					elem.SetType(ocsd.GenElemAddrUnknown)
				}
				if d.Config.CycleAcc() {
					elem.SetCycleCount(d.remainCC(packetIn, atomsNum, isCCPacket))
				}
				d.SentUnknown = true
			}
			atomsNum = 0 // clear all
		} else {
			if atomsNum > 0 {
				val := ocsd.AtomN
				if (enBits & 0x1) == 1 {
					val = ocsd.AtomE
				}

				// Follow instructions for this atom
				d.codeFollower.Isa = isa
				d.codeFollower.InstrInfo.ISA = isa
				followRes, errCF := d.codeFollower.FollowSingleAtom(ocsd.VAddr(d.iAddr), val)
				if errCF != nil && !errors.Is(errCF, ocsd.ErrMemNacc) {
					return ocsd.ErrFail
				}

				if followRes.NumInstr > 0 {
					elem, err = d.getNextOpElem()
					if err != nil {
						return ocsd.ErrFail
					}
					elem.SetType(ocsd.GenElemInstrRange)
					elem.StartAddr = followRes.RangeSt
					elem.EndAddr = followRes.RangeEn
					elem.Payload.NumInstrRange = followRes.NumInstr

					instrInfo := &followRes.InstrInfo
					elem.LastInstrExecuted = val == ocsd.AtomE
					elem.LastInstrType = instrInfo.Type
					elem.LastInstrSubtype = instrInfo.Subtype
					elem.LastInstrSize = instrInfo.InstrSize
					elem.LastInstrCond = instrInfo.IsConditional != 0
					elem.ISA = isa

					if d.Config.CycleAcc() {
						elem.SetCycleCount(d.atomCC(packetIn, atomsNum, isCCPacket))
					}

					d.iAddr = uint64(followRes.NextAddr)
					isa = instrInfo.NextISA

					if !followRes.HasNext {
						d.NeedAddr = true
						d.SentUnknown = false
					}
				}

				if errors.Is(errCF, ocsd.ErrMemNacc) {
					if d.numOutElem() > 0 && d.outElemType(d.numOutElem()-1) == ocsd.GenElemInstrRange {
						d.queuePendingNacc(uint64(followRes.NaccAddr), memSpace)
					} else {
						elem, err = d.getNextOpElem()
						if err == nil {
							elem.SetType(ocsd.GenElemAddrNacc)
							elem.StartAddr = ocsd.VAddr(followRes.NaccAddr)
							elem.Payload.ExceptionNum = uint32(memSpace)
						}
					}
					d.NeedAddr = true
					d.SentUnknown = false
				}
			} else if d.Config.CycleAcc() {
				// CC only packet (atomsNum == 0)
				elem, err := d.getNextOpElem()
				if err != nil {
					return ocsd.ErrFail
				}
				elem.SetType(ocsd.GenElemCycleCount)
				elem.SetCycleCount(d.remainCC(packetIn, atomsNum, isCCPacket))
			}
		}

		// clearAtom
		enBits >>= 1
		if atomsNum > 0 {
			atomsNum--
		}
		if atomsNum == 0 {
			break
		}
	}

	numElem := d.numOutElem()
	if numElem >= 1 {
		if d.outElemType(numElem-1) == ocsd.GenElemInstrRange {
			d.pendLastNOutElem(1)
		}
	}

	if d.outElemToSend() {
		// caller will compute next state via nextSendOrDecodeState
	}

	return nil
}

// NewConfiguredPktProc creates an ETMv3 packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETMv3 config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID
	proc := NewPktProc(cfg)
	return proc, nil
}

// NewConfiguredPktDecode creates an ETMv3 packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktDecode, error) {
	_ = instID
	// No explicit source provided for typed constructor.
	return NewPktDecode(cfg, mem, instr, nil)
}

// NewConfiguredPktDecodeWithDeps creates an ETMv3 decoder and injects dependencies.
// source is the pull-based PacketReader to use.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode, source ocsd.PacketReader[Packet]) (*PktDecode, error) {
	_ = instID
	dec, err := NewPktDecode(cfg, mem, instr, source)
	if err != nil {
		return nil, err
	}
	return dec, nil
}

// NewConfiguredPipeline creates and wires a typed ETMv3 processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecodeWithDeps(instID, cfg, mem, instr, proc)
	if err != nil {
		return nil, nil, err
	}
	return proc, dec, nil
}

// NewConfiguredPipelineWithDeps creates and wires an ETMv3 processor/decoder pair with dependencies.
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecodeWithDeps(instID, cfg, mem, instr, proc)
	if err != nil {
		return nil, nil, err
	}
	return proc, dec, nil
}

// --- ElemList replacements ---

func (d *PktDecode) nextOutElem(index ocsd.TrcIndex) *ocsd.TraceElement {
	if d.outCount >= len(d.outBuf) {
		panic("etmv3: outBuf overflow")
	}
	e := &d.outBuf[d.outCount]
	e.index = index
	e.traceID = d.csID

	// FIX: hard-zero the reused element to prevent state bleeding across packets.
	e.elem = ocsd.TraceElement{}
	e.elem.Init()
	e.elem.TraceID = d.csID

	d.outCount++
	return &e.elem
}

func (d *PktDecode) pendLastNOutElem(n int) {
	if n > 0 && n <= d.outCount {
		start := d.outCount - n
		for i := range n {
			d.pendBuf[i] = d.outBuf[start+i]
		}
		d.pendCount = n
		d.outCount = start
	}
}

func (d *PktDecode) commitAllPendOutElem() {
	if d.pendCount == 0 {
		return
	}
	if d.outCount+d.pendCount > len(d.outBuf) {
		panic("etmv3: outBuf overflow on commit")
	}

	if d.outCount > 0 {
		for i := d.outCount - 1; i >= 0; i-- {
			d.outBuf[i+d.pendCount] = d.outBuf[i]
		}
	}

	for i := 0; i < d.pendCount; i++ {
		d.outBuf[i] = d.pendBuf[i]
	}

	d.outCount += d.pendCount
	d.pendCount = 0
}

func (d *PktDecode) cancelPendOutElem() {
	d.pendCount = 0
}

func (d *PktDecode) outElemToSend() bool {
	return d.outCount > 0
}

func (d *PktDecode) numOutElem() int {
	return d.outCount
}

func (d *PktDecode) outElemType(entryN int) ocsd.GenElemType {
	if entryN >= 0 && entryN < d.outCount {
		return d.outBuf[entryN].elem.ElemType
	}
	return ocsd.GenElemUnknown
}
