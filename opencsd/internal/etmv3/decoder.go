package etmv3

import (
	"errors"
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

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
	common.DecoderBase
	Config       *Config
	CurrPacketIn *Packet
	lastErr      error

	currState  decoderState
	unsyncInfo common.UnsyncInfo

	codeFollower *common.CodeFollower

	iAddr       uint64
	needAddr    bool
	sentUnknown bool
	waitISync   bool

	peContext      *ocsd.PEContext
	outputElemList *common.GenElemList
	pendingNacc    bool
	pendingNaccIdx ocsd.TrcIndex
	pendingNaccAdr uint64
	pendingNaccMem ocsd.MemSpaceAcc

	csID uint8
}

// NewPktDecode creates a new ETMv3 trace decoder.
func NewPktDecode(cfg *Config, logger ocsd.Logger) *PktDecode {
	instID := 0
	if cfg != nil {
		instID = int(cfg.TraceID())
	}

	d := &PktDecode{
		DecoderBase: common.DecoderBase{
			Name: fmt.Sprintf("DCD_ETMV3_%d", instID),
			BaseLogger: common.BaseLogger{
				Logger:       logger,
				ErrVerbosity: ocsd.ErrSevNone,
			},
			UsesMemAccess: true,
			UsesIDecode:   true,
		},
		peContext:      &ocsd.PEContext{},
		outputElemList: common.NewGenElemList(),
	}
	d.codeFollower = common.NewCodeFollowerWithInterfaces(d.MemAccess, d.InstrDecode)
	d.configureDecoder()
	if cfg != nil {
		_ = d.SetProtocolConfig(cfg)
	}
	return d
}

func (d *PktDecode) SetMemAccess(mem common.TargetMemAccess) {
	d.MemAccess = mem
	if d.codeFollower != nil {
		d.codeFollower.SetInterfaces(d.MemAccess, d.InstrDecode)
	}
}

func (d *PktDecode) SetInstrDecode(decoder common.InstrDecode) {
	d.InstrDecode = decoder
	if d.codeFollower != nil {
		d.codeFollower.SetInterfaces(d.MemAccess, d.InstrDecode)
	}
}

// SetTraceElemOut satisfies dcdtree's traceElemSetterOwner interface.
func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) { d.TraceElemOut = out }

// traceElemOutIf returns the downstream GenElemProcessor (used as a func reference for outputElemList).
func (d *PktDecode) traceElemOutIf() ocsd.GenElemProcessor { return d.TraceElemOut }

// SetNeedsMemAccess controls whether memory access is required for decode.
func (d *PktDecode) SetNeedsMemAccess(needs bool) { d.UsesMemAccess = needs }

// SetNeedsInstructionDecode controls whether instruction decode is required.
func (d *PktDecode) SetNeedsInstructionDecode(needs bool) { d.UsesIDecode = needs }

func (d *PktDecode) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *Packet) ocsd.DatapathResp {
	resp := ocsd.RespCont
	d.lastErr = nil
	if d.codeFollower != nil {
		d.codeFollower.SetInterfaces(d.MemAccess, d.InstrDecode)
	}

	if reason := d.DecodeNotReadyReason(); reason != "" {
		d.lastErr = fmt.Errorf("%w: %s", ocsd.ErrNotInit, reason)
		return ocsd.RespFatalNotInit
	}

	switch op {
	case ocsd.OpData:
		if pktIn == nil {
			d.lastErr = ocsd.ErrInvalidParamVal
			resp = ocsd.RespFatalInvalidParam
		} else {
			d.CurrPacketIn = pktIn
			d.IndexCurrPkt = indexSOP
			resp = d.ProcessPacket()
		}
	case ocsd.OpEOT:
		resp = d.OnEOT()
	case ocsd.OpFlush:
		resp = d.OnFlush()
	case ocsd.OpReset:
		resp = d.OnReset()
	default:
		d.lastErr = ocsd.ErrInvalidParamVal
		resp = ocsd.RespFatalInvalidOp
	}
	return resp
}

func (d *PktDecode) configureDecoder() {
	d.csID = 0
	d.resetDecoder()
	d.unsyncInfo = common.UnsyncInitDecoder

	d.outputElemList.SetSendIf(d.traceElemOutIf)
}

func (d *PktDecode) resetDecoder() {
	d.currState = noSync
	d.needAddr = true
	d.sentUnknown = false
	d.waitISync = false
	d.pendingNacc = false
	d.pendingNaccIdx = 0
	d.pendingNaccAdr = 0
	d.pendingNaccMem = ocsd.MemSpaceNone
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
	d.ConfigInitOK = true

	d.csID = d.Config.TraceID()

	if d.Config.TraceMode() != TMInstrOnly {
		err := ocsd.ErrHWCfgUnsupp
		d.lastErr = fmt.Errorf("%w: ETMv3 trace decoder: data trace decode not yet supported", err)
		return err
	}

	archProfile := ocsd.ArchProfile{
		Arch:    d.Config.ArchVer,
		Profile: d.Config.CoreProf,
	}

	d.codeFollower.SetArchProfile(archProfile)
	d.codeFollower.SetTraceID(d.csID)
	d.outputElemList.SetCSID(d.csID)

	return nil
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = common.UnsyncResetDecoder
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
	resp = d.outputElemList.SendElements()
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
		d.lastErr = err
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}
	elem.SetType(ocsd.GenElemEOTrace)
	elem.Payload.UnsyncEOTInfo = ocsd.UnsyncEOT
	d.outputElemList.CommitAllPendElem()

	d.currState = sendPkts
	resp = d.outputElemList.SendElements()
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
			d.lastErr = fmt.Errorf("unknown decoder state")
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
		resp := d.processISync(packetIn.Type == PktISyncCycle, true)
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
	resp := d.outputElemList.SendElements()
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
		d.lastErr = err
		d.unsyncInfo = common.UnsyncBadPacket
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
	if pktType == PktTimestamp || (d.Config.IsCycleAcc() && (pktType == PktCycleCount || pktType == PktPHdr)) {
		return true
	}
	return false
}

func (d *PktDecode) sendUnsyncPacket() ocsd.DatapathResp {
	elem, err := d.getNextOpElem()
	if err != nil {
		d.lastErr = err
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}

	elem.SetType(ocsd.GenElemNoSync)
	elem.Payload.UnsyncEOTInfo = ocsd.UnsyncInfo(d.unsyncInfo)
	return d.outputElemList.SendElements()
}

func (d *PktDecode) decodePacket() (resp ocsd.DatapathResp, done bool) {
	resp = ocsd.RespCont
	done = false

	packetIn := d.CurrPacketIn

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
		d.lastErr = fmt.Errorf("%w: trace packet synchronisation lost", ocsd.ErrBadPacketSeq)
		d.unsyncInfo = common.UnsyncBadPacket
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
		resp = d.processISync(packetIn.Type == PktISyncCycle, false)
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
		d.lastErr = fmt.Errorf("%w: invalid packet type: data tracing decode not supported", ocsd.ErrHWCfgUnsupp)
		resp = ocsd.RespFatalInvalidData
	case PktBadSequence:
		d.lastErr = fmt.Errorf("%w: bad packet sequence", ocsd.ErrBadPacketSeq)
		resp = ocsd.RespFatalInvalidData
	case PktReserved:
		fallthrough
	default:
		d.lastErr = fmt.Errorf("%w: reserved or unknown packet ID", ocsd.ErrBadPacketSeq)
		resp = ocsd.RespFatalInvalidData
	}

	if err != nil {
		d.lastErr = err
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr, true
	}

	if resp == ocsd.RespFatalInvalidData {
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		return resp, true
	}

	if d.outputElemList.ElemToSend() {
		// caller (handleDecodePkts) will compute next state via nextSendOrDecodeState
	}
	done = !d.outputElemList.ElemToSend()
	return resp, done
}

func (d *PktDecode) setNeedAddr(needAddr bool) {
	d.needAddr = needAddr
	d.sentUnknown = false
}

func (d *PktDecode) processISync(withCC bool, firstSync bool) ocsd.DatapathResp {
	packetIn := d.CurrPacketIn
	ctxtUpdate := packetIn.Context.UpdatedC || packetIn.Context.UpdatedV || packetIn.Context.Updated

	elem, err := d.getNextOpElem()
	if err != nil {
		d.lastErr = err
		d.unsyncInfo = common.UnsyncBadPacket
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
			d.lastErr = err
			d.unsyncInfo = common.UnsyncBadPacket
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
		d.codeFollower.SetISA(packetIn.CurrISA)

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
		d.setNeedAddr(false)
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
	d.setNeedAddr(false)
	d.codeFollower.SetISA(packetIn.CurrISA)

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
			d.lastErr = err
			d.unsyncInfo = common.UnsyncBadPacket
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
				d.lastErr = err
				d.unsyncInfo = common.UnsyncBadPacket
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

	isCCPacket := d.Config.IsCycleAcc()

	memSpace := ocsd.MemSpaceN
	if d.peContext.SecurityLevel == ocsd.SecSecure {
		memSpace = ocsd.MemSpaceS
	}
	var elem *ocsd.TraceElement
	var err error

	d.codeFollower.SetMemSpace(memSpace)

	for {
		if d.needAddr {
			if !d.sentUnknown || d.Config.IsCycleAcc() {
				elem, err := d.getNextOpElem()
				if err != nil {
					d.lastErr = err
					d.unsyncInfo = common.UnsyncBadPacket
					d.resetDecoder()
					return ocsd.RespFatalSysErr
				}
				if d.sentUnknown || atomsNum == 0 {
					elem.SetType(ocsd.GenElemCycleCount)
				} else {
					elem.SetType(ocsd.GenElemAddrUnknown)
				}
				if d.Config.IsCycleAcc() {
					elem.SetCycleCount(d.remainCC(packetIn, atomsNum, isCCPacket))
				}
				d.sentUnknown = true
			}
			atomsNum = 0 // clear all
		} else {
			if atomsNum > 0 {
				val := ocsd.AtomN
				if (enBits & 0x1) == 1 {
					val = ocsd.AtomE
				}

				// Follow instructions for this atom
				d.codeFollower.SetISA(isa)
				errCF := d.codeFollower.FollowSingleAtom(ocsd.VAddr(d.iAddr), val)
				if errCF != nil && !errors.Is(errCF, ocsd.ErrMemNacc) {
					d.lastErr = fmt.Errorf("%w: error following atom", errCF)
					return ocsd.RespFatalSysErr
				}

				if d.codeFollower.NumInstructs() > 0 {
					elem, err = d.getNextOpElem()
					if err != nil {
						d.lastErr = err
						return ocsd.RespFatalSysErr
					}
					elem.SetType(ocsd.GenElemInstrRange)
					elem.StartAddr = d.codeFollower.RangeSt()
					elem.EndAddr = d.codeFollower.RangeEn()
					elem.Payload.NumInstrRange = d.codeFollower.NumInstructs()

					instrInfo := d.codeFollower.InstrInfo()
					elem.LastInstrExecuted = val == ocsd.AtomE
					elem.LastInstrType = instrInfo.Type
					elem.LastInstrSubtype = instrInfo.Subtype
					elem.LastInstrSize = instrInfo.InstrSize
					elem.LastInstrCond = instrInfo.IsConditional != 0
					elem.ISA = isa

					if d.Config.IsCycleAcc() {
						elem.SetCycleCount(d.atomCC(packetIn, atomsNum, isCCPacket))
					}

					d.iAddr = uint64(d.codeFollower.NextAddr())
					isa = instrInfo.NextISA

					if !d.codeFollower.HasNext() {
						d.setNeedAddr(true)
					}
				}

				if errors.Is(errCF, ocsd.ErrMemNacc) {
					if d.outputElemList.NumElem() > 0 && d.outputElemList.ElemType(d.outputElemList.NumElem()-1) == ocsd.GenElemInstrRange {
						d.queuePendingNacc(uint64(d.codeFollower.NaccAddr()), memSpace)
					} else {
						elem, err = d.getNextOpElem()
						if err == nil {
							elem.SetType(ocsd.GenElemAddrNacc)
							elem.StartAddr = ocsd.VAddr(d.codeFollower.NaccAddr())
							elem.Payload.ExceptionNum = uint32(memSpace)
						}
					}
					d.setNeedAddr(true)
					d.codeFollower.ClearNaccError()
				}
			} else if d.Config.IsCycleAcc() {
				// CC only packet (atomsNum == 0)
				elem, err := d.getNextOpElem()
				if err != nil {
					d.lastErr = err
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
	proc := NewPktProc(cfg, nil)
	return proc, nil
}

// NewConfiguredPktDecode creates an ETMv3 packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETMv3 config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID
	dec := NewPktDecode(cfg, nil)
	return dec, nil
}

// NewConfiguredPipeline creates and wires a typed ETMv3 processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(dec)
	return proc, dec, nil
}
