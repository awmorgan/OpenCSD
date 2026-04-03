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

type pktDecodeSink struct {
	decoder *PktDecode
}

func (s *pktDecodeSink) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	if s == nil || s.decoder == nil || elem == nil {
		return nil
	}
	d := s.decoder
	if d.traceElemOut == nil {
		e := traceElemEvent{indexSOP, trcChanID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	err := d.traceElemOut.TraceElemIn(indexSOP, trcChanID, elem)
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
	outputElemList *common.ElemList
	pendingNacc    bool
	pendingNaccIdx ocsd.TrcIndex
	pendingNaccAdr uint64
	pendingNaccMem ocsd.MemSpaceAcc

	csID uint8

	// Pull-iterator fields (for API consistency with other decoders)
	pendingElements []traceElemEvent
	collectElements bool
	sink            *pktDecodeSink
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
		Name:           fmt.Sprintf("DCD_ETMV3_%d", instID),
		MemAccess:      mem,
		InstrDecode:    instr,
		peContext:      &ocsd.PEContext{},
		outputElemList: common.NewElemList(),
		codeFollower:   codeFollower,
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
	return d.sink.TraceElemIn(d.IndexCurrPkt, traceID, elem)
}

// OutputTraceElementIdx sends an element at an explicit index.
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	return d.sink.TraceElemIn(idx, traceID, elem)
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

func (d *PktDecode) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	resp := ocsd.RespCont
	var packetErr error

	switch op {
	case ocsd.OpData:
		if pktIn == nil {
			packetErr = ocsd.ErrInvalidParamVal
			resp = ocsd.RespFatalInvalidParam
		} else {
			d.CurrPacketIn = pktIn
			d.IndexCurrPkt = indexSOP
			d.collectElements = true
			resp = d.ProcessPacket()
			d.collectElements = false
			// Drain queued elements only when using legacy push sink wiring.
			if ocsd.DataRespIsCont(resp) && d.traceElemOut != nil {
				packetErr = nil
				for {
					_, _, _, nextErr := d.NextElement()
					if errors.Is(nextErr, io.EOF) {
						break
					}
					if nextErr != nil {
						packetErr = nextErr
						resp = ocsd.DataRespFromErr(nextErr)
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
		packetErr = ocsd.ErrInvalidParamVal
		resp = ocsd.RespFatalInvalidOp
	}
	return ocsd.DataErrFromResp(resp, packetErr)
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

func (d *PktDecode) configureDecoder() {
	d.csID = 0
	d.resetDecoder()
	d.unsyncInfo = ocsd.UnsyncInitDecoder
	if d.sink == nil {
		d.sink = &pktDecodeSink{decoder: d}
	}

	d.outputElemList.SetSendIf(d.sink)
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
	d.outputElemList.Reset()
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
	d.outputElemList.SetCSID(d.csID)

	return nil
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	d.resetDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if d.outputElemList.NumElem() == 0 && !d.pendingNacc {
		return resp
	}

	d.outputElemList.CommitAllPendElem()
	resp = d.emitPendingNacc()
	if !ocsd.DataRespIsCont(resp) {
		return resp
	}

	if d.outputElemList.NumElem() == 0 {
		d.currState = d.nextDecodeState()
		return resp
	}

	d.currState = sendPkts
	resp = ocsd.DataRespFromErr(d.outputElemList.SendElements())
	if ocsd.DataRespIsCont(resp) {
		d.currState = d.nextDecodeState()
	}
	return resp
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	d.outputElemList.CommitAllPendElem()
	resp = d.emitPendingNacc()
	if !ocsd.DataRespIsCont(resp) {
		return resp
	}

	elem, err := d.getNextOpElem()
	if err != nil {
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}
	elem.SetType(ocsd.GenElemEOTrace)
	elem.Payload.UnsyncEOTInfo = ocsd.UnsyncEOT
	d.outputElemList.CommitAllPendElem()

	d.currState = sendPkts
	resp = ocsd.DataRespFromErr(d.outputElemList.SendElements())
	if ocsd.DataRespIsCont(resp) {
		d.currState = decodePkts
	}

	return resp
}

func (d *PktDecode) ProcessPacket() ocsd.DatapathResp {
	if d.Config == nil {
		return ocsd.RespFatalNotInit
	}

	var resp ocsd.DatapathResp
	for {
		var next decoderState
		var done bool
		switch d.currState {
		case noSync:
			next, resp, done = d.handleNoSync()
		case waitAsync:
			next, resp, done = d.handleWaitAsync()
		case waitISync:
			next, resp, done = d.handleWaitISync()
		case decodePkts:
			next, resp, done = d.handleDecodePkts()
		case sendPkts:
			next, resp, done = d.handleSendPkts()
		default:
			d.resetDecoder()
			return ocsd.RespFatalSysErr
		}
		d.currState = next
		if done {
			return resp
		}
	}
}

func (d *PktDecode) handleNoSync() (decoderState, ocsd.DatapathResp, bool) {
	resp := d.sendUnsyncPacket()
	return waitAsync, resp, false // continue to waitAsync
}

func (d *PktDecode) handleWaitAsync() (decoderState, ocsd.DatapathResp, bool) {
	if d.CurrPacketIn.Type == PktASync {
		return waitISync, ocsd.RespCont, true
	}
	return waitAsync, ocsd.RespCont, true
}

func (d *PktDecode) handleWaitISync() (decoderState, ocsd.DatapathResp, bool) {
	d.waitISync = true
	packetIn := d.CurrPacketIn
	if packetIn.Type == PktISync || packetIn.Type == PktISyncCycle {
		resp := d.processISync(true)
		d.waitISync = false
		return d.nextSendOrDecodeState(), resp, false
	}
	if d.preISyncValid(packetIn.Type) {
		next, resp, done := d.handleDecodePkts()
		return next, resp, done
	}
	return waitISync, ocsd.RespCont, true
}

func (d *PktDecode) handleDecodePkts() (decoderState, ocsd.DatapathResp, bool) {
	resp, done := d.decodePacket()
	next := d.nextSendOrDecodeState()
	return next, resp, done
}

func (d *PktDecode) handleSendPkts() (decoderState, ocsd.DatapathResp, bool) {
	resp := ocsd.DataRespFromErr(d.outputElemList.SendElements())
	if ocsd.DataRespIsCont(resp) {
		return d.nextDecodeState(), resp, true
	}
	return sendPkts, resp, true
}

// nextSendOrDecodeState returns sendPkts if there are elements to send, otherwise the next decode state.
func (d *PktDecode) nextSendOrDecodeState() decoderState {
	if d.outputElemList.ElemToSend() {
		return sendPkts
	}
	return d.nextDecodeState()
}

func (d *PktDecode) getNextOpElem() (*ocsd.TraceElement, error) {
	elem := d.outputElemList.NextElem(d.IndexCurrPkt)
	if elem == nil {
		return nil, fmt.Errorf("%w: Memory Allocation Error - fatal", ocsd.ErrMem)
	}
	return elem, nil
}

func (d *PktDecode) getNextOpElemAt(index ocsd.TrcIndex) (*ocsd.TraceElement, error) {
	elem := d.outputElemList.NextElem(index)
	if elem == nil {
		return nil, fmt.Errorf("%w: Memory Allocation Error - fatal", ocsd.ErrMem)
	}
	return elem, nil
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

func (d *PktDecode) emitPendingNacc() ocsd.DatapathResp {
	if !d.pendingNacc {
		return ocsd.RespCont
	}

	elem, err := d.getNextOpElemAt(d.pendingNaccIdx)
	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}

	elem.SetType(ocsd.GenElemAddrNacc)
	elem.StartAddr = ocsd.VAddr(d.pendingNaccAdr)
	elem.Payload.ExceptionNum = uint32(d.pendingNaccMem)
	d.clearPendingNacc()
	return ocsd.RespCont
}

func (d *PktDecode) preISyncValid(pktType PktType) bool {
	if pktType == PktTimestamp || (d.Config.CycleAcc() && (pktType == PktCycleCount || pktType == PktPHdr)) {
		return true
	}
	return false
}

func (d *PktDecode) sendUnsyncPacket() ocsd.DatapathResp {
	elem, err := d.getNextOpElem()
	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}

	elem.SetType(ocsd.GenElemNoSync)
	elem.Payload.UnsyncEOTInfo = ocsd.UnsyncInfo(d.unsyncInfo)
	return ocsd.DataRespFromErr(d.outputElemList.SendElements())
}

func (d *PktDecode) decodePacket() (resp ocsd.DatapathResp, done bool) {
	resp = ocsd.RespCont
	done = false

	packetIn := d.CurrPacketIn
	if packetIn.Err != nil {
		switch packetIn.displayType() {
		case PktIncompleteEOT:
			return ocsd.RespCont, true
		case PktBadSequence, PktBadTraceMode, PktReserved:
			d.unsyncInfo = ocsd.UnsyncBadPacket
			d.resetDecoder()
			return ocsd.RespFatalInvalidData, true
		}
	}

	if packetIn.Type != PktBranchAddress {
		d.outputElemList.CommitAllPendElem()
		resp = d.emitPendingNacc()
		if !ocsd.DataRespIsCont(resp) {
			return resp, true
		}
	}

	var elem *ocsd.TraceElement
	var err error

	switch packetIn.Type {
	case PktNotSync:
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr, true

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
		resp = d.processBranchAddr()
	case PktISyncCycle, PktISync:
		resp = d.processISync(false)
	case PktPHdr:
		resp = d.processPHdr()
	case PktContextID:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemPeContext)
			d.peContext.ContextID = packetIn.Context.CtxtID
			d.peContext.SetCtxtIDValid(true)
			elem.Context = *d.peContext
		}
	case PktVMID:
		elem, err = d.getNextOpElem()
		if err == nil {
			elem.SetType(ocsd.GenElemPeContext)
			d.peContext.VMID = uint32(packetIn.Context.VMID)
			d.peContext.SetVMIDValid(true)
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
		resp = ocsd.RespFatalInvalidData
	case PktBadSequence:
		resp = ocsd.RespFatalInvalidData
	case PktReserved:
		fallthrough
	default:
		resp = ocsd.RespFatalInvalidData
	}

	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr, true
	}

	if resp == ocsd.RespFatalInvalidData {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return resp, true
	}

	if d.outputElemList.ElemToSend() {
		// caller (handleDecodePkts) will compute next state via nextSendOrDecodeState
	}
	done = !d.outputElemList.ElemToSend()
	return resp, done
}

func (d *PktDecode) processISync(firstSync bool) ocsd.DatapathResp {
	packetIn := d.CurrPacketIn
	ctxtUpdate := packetIn.Context.UpdatedC || packetIn.Context.UpdatedV || packetIn.Context.Updated

	elem, err := d.getNextOpElem()
	if err != nil {
		d.unsyncInfo = ocsd.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr
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
			return ocsd.RespFatalSysErr
		}
	}

	if ctxtUpdate || firstSync {
		if firstSync {
			d.peContext = &ocsd.PEContext{}
		}

		if packetIn.Context.UpdatedC {
			d.peContext.ContextID = packetIn.Context.CtxtID
			d.peContext.SetCtxtIDValid(true)
		}
		if packetIn.Context.UpdatedV {
			d.peContext.VMID = uint32(packetIn.Context.VMID)
			d.peContext.SetVMIDValid(true)
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
			d.peContext.SetELValid(true)
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

	if d.outputElemList.ElemToSend() {
		// caller will compute next state via nextSendOrDecodeState
	}

	return ocsd.RespCont
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

func (d *PktDecode) processBranchAddr() ocsd.DatapathResp {
	packetIn := d.CurrPacketIn
	updatePEContext := false

	if packetIn.ExceptionCancel {
		d.outputElemList.CancelPendElem()
		d.clearPendingNacc()
	} else {
		d.outputElemList.CommitAllPendElem()
		resp := d.emitPendingNacc()
		if !ocsd.DataRespIsCont(resp) {
			return resp
		}
	}

	d.iAddr = packetIn.Addr
	d.NeedAddr = false
	d.SentUnknown = false
	d.codeFollower.Isa = packetIn.CurrISA
	d.codeFollower.InstrInfo.ISA = packetIn.CurrISA

	if packetIn.Context.UpdatedC || packetIn.Context.UpdatedV || packetIn.Context.Updated {
		if packetIn.Context.UpdatedC && (!d.peContext.CtxtIDValid() || d.peContext.ContextID != packetIn.Context.CtxtID) {
			d.peContext.ContextID = packetIn.Context.CtxtID
			d.peContext.SetCtxtIDValid(true)
			updatePEContext = true
		}
		if packetIn.Context.UpdatedV && (!d.peContext.VMIDValid() || d.peContext.VMID != uint32(packetIn.Context.VMID)) {
			d.peContext.VMID = uint32(packetIn.Context.VMID)
			d.peContext.SetVMIDValid(true)
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
			if !d.peContext.ELValid() || el != d.peContext.ExceptionLevel {
				d.peContext.ExceptionLevel = el
				d.peContext.SetELValid(true)
				updatePEContext = true
			}
		}
	}

	if updatePEContext {
		elem, err := d.getNextOpElem()
		if err != nil {
			d.unsyncInfo = ocsd.UnsyncBadPacket
			d.resetDecoder()
			return ocsd.RespFatalSysErr
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
				return ocsd.RespFatalSysErr
			}
			elem.SetType(ocsd.GenElemException)
			elem.Payload.ExceptionNum = uint32(packetIn.Exception.Number)
		}
	}

	if d.outputElemList.ElemToSend() {
		// caller will compute next state via nextSendOrDecodeState
	}

	return ocsd.RespCont
}

func (d *PktDecode) pendExceptionReturn() {
	pendElem := 1
	if d.Config.CoreProf != ocsd.ProfileCortexM {
		nElem := d.outputElemList.NumElem()
		if nElem > 1 {
			if d.outputElemList.ElemType(nElem-2) == ocsd.GenElemInstrRange {
				pendElem = 2
			}
		}
	}
	d.outputElemList.PendLastNElem(pendElem)
}

// processPHdr uses the etmv3Atoms struct pattern natively in Go inline since it doesn't need external exposure.
func (d *PktDecode) processPHdr() ocsd.DatapathResp {
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
					return ocsd.RespFatalSysErr
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
					return ocsd.RespFatalSysErr
				}

				if followRes.NumInstr > 0 {
					elem, err = d.getNextOpElem()
					if err != nil {
						return ocsd.RespFatalSysErr
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
					if d.outputElemList.NumElem() > 0 && d.outputElemList.ElemType(d.outputElemList.NumElem()-1) == ocsd.GenElemInstrRange {
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
					return ocsd.RespFatalSysErr
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

	numElem := d.outputElemList.NumElem()
	if numElem >= 1 {
		if d.outputElemList.ElemType(numElem-1) == ocsd.GenElemInstrRange {
			d.outputElemList.PendLastNElem(1)
		}
	}

	if d.outputElemList.ElemToSend() {
		// caller will compute next state via nextSendOrDecodeState
	}

	return ocsd.RespCont
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
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, out ocsd.GenElemProcessor, mem common.TargetMemAccess, instr common.InstrDecode) (*PktDecode, error) {
	dec, err := NewConfiguredPktDecode(instID, cfg, mem, instr)
	if err != nil {
		return nil, err
	}
	dec.SetTraceElemOut(out)
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
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, out ocsd.GenElemProcessor, mem common.TargetMemAccess, instr common.InstrDecode) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecodeWithDeps(instID, cfg, out, mem, instr)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(dec)
	return proc, dec, nil
}
