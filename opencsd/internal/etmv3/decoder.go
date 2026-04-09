package etmv3

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

func (d *PktDecode) pushOutputElement(index ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	if d == nil || elem == nil {
		return nil
	}
	if d.traceElemOut == nil {
		e := traceElemEvent{index, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	err := d.traceElemOut.TraceElemIn(index, traceID, elem)
	if ocsd.IsDataContErr(err) {
		return nil
	}
	if ocsd.IsDataWaitErr(err) {
		return ocsd.ErrWait
	}
	return err
}

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

	codeFollower *common.CodeFollower

	iAddr       uint64
	NeedAddr    bool
	SentUnknown bool
	waitISync   bool

	peContext      *ocsd.PEContext
	outElems       []ocsd.TraceElement
	outElemsIdx    []ocsd.TrcIndex
	numPendOut     int
	pendingNacc    bool
	pendingNaccIdx ocsd.TrcIndex
	pendingNaccAdr uint64
	pendingNaccMem ocsd.MemSpaceAcc

	csID            uint8
	pendingElements []traceElemEvent
	collectElements bool
}

func (d *PktDecode) ApplyFlags(flags uint32) error { return nil }

// NewPktDecode creates a new ETMv3 trace decoder.
func NewPktDecode(cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktDecode, error) {
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
	d.configureDecoder()
	if err := d.SetProtocolConfig(cfg); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *PktDecode) SetMemAccess(mem common.TargetMemAccess) error {
	if mem == nil {
		return fmt.Errorf("%w: ETMv3 mem access cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if d.codeFollower != nil {
		if err := d.codeFollower.SetInterfaces(mem, d.InstrDecode); err != nil {
			return err
		}
	}
	d.MemAccess = mem
	return nil
}

func (d *PktDecode) SetInstrDecode(decoder common.InstrDecode) error {
	if decoder == nil {
		return fmt.Errorf("%w: ETMv3 instruction decoder cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if d.codeFollower != nil {
		if err := d.codeFollower.SetInterfaces(d.MemAccess, decoder); err != nil {
			return err
		}
	}
	d.InstrDecode = decoder
	return nil
}

// SetTraceElemOut satisfies dcdtree's traceElemSetterOwner interface.
func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) {
	d.traceElemOut = out
}

// OutputTraceElement sends an element using IndexCurrPkt.
func (d *PktDecode) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error {
	return d.pushOutputElement(d.IndexCurrPkt, traceID, elem)
}

// OutputTraceElementIdx sends an element at an explicit index.
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	return d.pushOutputElement(idx, traceID, elem)
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

// Write is the explicit packet data entrypoint used by split interfaces.
func (d *PktDecode) Write(indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	if pktIn == nil {
		return ocsd.ErrInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = indexSOP
	d.collectElements = true
	err := d.ProcessPacket()
	d.collectElements = false

	d.flushOutputElements()

	// Drain queued elements only when using legacy push sink wiring.
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

func (d *PktDecode) flushOutputElements() {
	traceID := d.csID
	committed := len(d.outElems) - d.numPendOut
	if committed <= 0 {
		return
	}
	for i := range committed {
		elem := cloneQueuedElem(&d.outElems[i])
		elem.TraceID = traceID
		_ = d.pushOutputElement(d.outElemsIdx[i], traceID, &elem)
	}
	copy(d.outElems, d.outElems[committed:])
	copy(d.outElemsIdx, d.outElemsIdx[committed:])
	d.outElems = d.outElems[:d.numPendOut]
	d.outElemsIdx = d.outElemsIdx[:d.numPendOut]
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
	d.pendingNacc = false
	d.pendingNaccIdx = 0
	d.pendingNaccAdr = 0
	d.pendingNaccMem = ocsd.MemSpaceNone
	d.pendingElements = d.pendingElements[:0]
	d.resetOutElems()
}

func (d *PktDecode) nextDecodeState() decoderState {
	if d.waitISync {
		return waitISync
	}
	return decodePkts
}

func (d *PktDecode) SetProtocolConfig(config *Config) error {
	d.Config = config
	if d.Config == nil {
		return ocsd.ErrNotInit
	}
	d.csID = d.Config.TraceID()

	if d.Config.TraceMode() != TMInstrOnly {
		err := ocsd.ErrHWCfgUnsupp
		return fmt.Errorf("%w: ETMv3 trace decoder: data trace decode not yet supported", err)
	}

	archProfile := ocsd.ArchProfile{
		Arch:    d.Config.ArchVer,
		Profile: d.Config.CoreProf,
	}

	d.codeFollower.Arch = archProfile
	d.codeFollower.InstrInfo.PeType = archProfile
	d.codeFollower.TraceID = d.csID

	return nil
}

func (d *PktDecode) OnReset() {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	d.resetDecoder()
}

func (d *PktDecode) OnFlush() error {
	if d.numOutElem() == 0 && !d.pendingNacc {
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

func (d *PktDecode) ProcessPacket() error {
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
	return NewPktDecode(cfg, mem, instr)
}

// NewConfiguredPktDecodeWithDeps creates an ETMv3 decoder and injects dependencies.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktDecode, error) {
	dec, err := NewConfiguredPktDecode(instID, cfg, mem, instr)
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
	dec, err := NewConfiguredPktDecode(instID, cfg, mem, instr)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(dec)
	return proc, dec, nil
}

// NewConfiguredPipelineWithDeps creates and wires an ETMv3 processor/decoder pair with dependencies.
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecodeWithDeps(instID, cfg, mem, instr)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(dec)
	return proc, dec, nil
}

// --- ElemList replacements ---

func (d *PktDecode) nextOutElem(index ocsd.TrcIndex) *ocsd.TraceElement {
	var e ocsd.TraceElement
	e.Init()
	d.outElems = append(d.outElems, e)
	d.outElemsIdx = append(d.outElemsIdx, index)
	elem := &d.outElems[len(d.outElems)-1]
	elem.TraceID = d.csID
	return elem
}

func (d *PktDecode) pendLastNOutElem(n int) {
	if n > 0 && n <= len(d.outElems) {
		d.numPendOut = n
	}
}

func (d *PktDecode) commitAllPendOutElem() {
	d.numPendOut = 0
}

func (d *PktDecode) cancelPendOutElem() {
	if d.numPendOut == 0 {
		return
	}
	start := len(d.outElems) - d.numPendOut
	d.outElems = d.outElems[:start]
	d.outElemsIdx = d.outElemsIdx[:start]
	d.numPendOut = 0
}

func (d *PktDecode) outElemToSend() bool {
	return len(d.outElems)-d.numPendOut > 0
}

func (d *PktDecode) numOutElem() int {
	return len(d.outElems)
}

func (d *PktDecode) outElemType(entryN int) ocsd.GenElemType {
	if entryN >= 0 && entryN < len(d.outElems) {
		return d.outElems[entryN].ElemType
	}
	return ocsd.GenElemUnknown
}

func (d *PktDecode) resetOutElems() {
	d.outElems = d.outElems[:0]
	d.outElemsIdx = d.outElemsIdx[:0]
	d.numPendOut = 0
}
