package etmv3

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/interfaces"
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

// PktDecode implements the ETMv3 packet decoder converting packets to generic TraceElements
// Ported from trc_pkt_decode_etmv3.cpp
type PktDecode struct {
	*common.PktDecodeBase[Packet, Config]

	currState  decoderState
	unsyncInfo common.UnsyncInfo

	codeFollower *common.CodeFollower

	iAddr        uint64
	bNeedAddr    bool
	bSentUnknown bool
	bWaitISync   bool

	peContext      *ocsd.PEContext
	outputElemList *common.GenElemList

	csID uint8
}

// NewPktDecode creates a new ETMv3 trace decoder
func NewPktDecode(instID int) *PktDecode {
	d := &PktDecode{
		peContext:      &ocsd.PEContext{},
		outputElemList: common.NewGenElemList(),
		codeFollower:   common.NewCodeFollower(),
	}
	d.PktDecodeBase = &common.PktDecodeBase[Packet, Config]{}
	d.InitPktDecodeBase(fmt.Sprintf("%s_%d", "DCD_ETMV3", instID))

	d.FnProcessPacket = d.ProcessPacket
	d.FnOnEOT = d.OnEOT
	d.FnOnReset = d.OnReset
	d.FnOnFlush = d.OnFlush
	d.FnOnProtocolConfig = d.OnProtocolConfig

	d.initDecoder()
	return d
}

func (d *PktDecode) initDecoder() {
	d.csID = 0
	d.resetDecoder()
	d.unsyncInfo = common.UnsyncInitDecoder

	// Need a cast / function property attachment in Go compared to C++ base classes
	d.codeFollower.InitInterfaces(&d.MemAccess, &d.InstrDecode)
	d.outputElemList.InitSendIf(&d.TraceElemOut)
}

func (d *PktDecode) resetDecoder() {
	d.currState = noSync
	d.bNeedAddr = true
	d.bSentUnknown = false
	d.bWaitISync = false
	d.outputElemList.Reset()
}

func (d *PktDecode) OnProtocolConfig() ocsd.Err {
	if d.Config == nil {
		return ocsd.ErrNotInit
	}

	d.csID = d.Config.TraceID()

	if d.Config.TraceMode() != TMInstrOnly {
		err := ocsd.ErrHWCfgUnsupp
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err, "ETMv3 trace decoder : data trace decode not yet supported"))
		return err
	}

	archProfile := ocsd.ArchProfile{
		Arch:    d.Config.ArchVer,
		Profile: d.Config.CoreProf,
	}

	d.codeFollower.SetArchProfile(archProfile)
	d.codeFollower.SetTraceID(d.csID)
	d.outputElemList.InitCSID(d.csID)

	return ocsd.OK
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = common.UnsyncResetDecoder
	d.resetDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if d.currState == sendPkts {
		resp = d.outputElemList.SendElements()
		if ocsd.DataRespIsCont(resp) {
			if d.bWaitISync {
				d.currState = waitISync
			} else {
				d.currState = decodePkts
			}
		}
	}
	return resp
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont

	pElem, err := d.getNextOpElem()
	if err != nil {
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}
	pElem.SetType(ocsd.GenElemEOTrace)
	pElem.Payload.UnsyncEOTInfo = ocsd.UnsyncEOT
	d.outputElemList.CommitAllPendElem()

	d.currState = sendPkts
	resp = d.outputElemList.SendElements()
	if ocsd.DataRespIsCont(resp) {
		d.currState = decodePkts
	}

	return resp
}

func (d *PktDecode) ProcessPacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	pktDone := false

	if d.Config == nil {
		return ocsd.RespFatalNotInit
	}

	for !pktDone {
		switch d.currState {
		case noSync:
			resp = d.sendUnsyncPacket()
			d.currState = waitAsync
		case waitAsync:
			packetIn := d.CurrPacketIn
			if packetIn.Type == PktASync {
				d.currState = waitISync
			}
			pktDone = true
		case waitISync:
			d.bWaitISync = true
			packetIn := d.CurrPacketIn
			if packetIn.Type == PktISync || packetIn.Type == PktISyncCycle {
				resp = d.processISync(packetIn.Type == PktISyncCycle, true)
				d.currState = sendPkts
				d.bWaitISync = false
			} else if d.preISyncValid(packetIn.Type) {
				resp = d.decodePacket(&pktDone)
			} else {
				pktDone = true
			}
		case decodePkts:
			resp = d.decodePacket(&pktDone)
		case sendPkts:
			resp = d.outputElemList.SendElements()
			if ocsd.DataRespIsCont(resp) {
				if d.bWaitISync {
					d.currState = waitISync
				} else {
					d.currState = decodePkts
				}
			}
			pktDone = true
		default:
			pktDone = true
			d.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrFail, "Unknown Decoder State"))
			d.resetDecoder()
			resp = ocsd.RespFatalSysErr
		}
	}
	return resp
}

func (d *PktDecode) getNextOpElem() (*ocsd.TraceElement, error) {
	pElem := d.outputElemList.GetNextElem(d.IndexCurrPkt)
	if pElem == nil {
		return nil, &common.Error{Code: ocsd.ErrMem, Idx: d.IndexCurrPkt, ChanID: d.csID, Message: "Memory Allocation Error - fatal"}
	}
	return pElem, nil
}

func (d *PktDecode) preISyncValid(pktType PktType) bool {
	if pktType == PktTimestamp || (d.Config.IsCycleAcc() && (pktType == PktCycleCount || pktType == PktPHdr)) {
		return true
	}
	return false
}

func (d *PktDecode) sendUnsyncPacket() ocsd.DatapathResp {
	pElem, err := d.getNextOpElem()
	if err != nil {
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}

	pElem.SetType(ocsd.GenElemNoSync)
	pElem.Payload.UnsyncEOTInfo = ocsd.UnsyncInfo(d.unsyncInfo)
	return d.outputElemList.SendElements()
}

func (d *PktDecode) decodePacket(pktDone *bool) ocsd.DatapathResp {
	resp := ocsd.RespCont
	*pktDone = false

	packetIn := d.CurrPacketIn

	if packetIn.Type != PktBranchAddress {
		d.outputElemList.CommitAllPendElem()
	}

	var pElem *ocsd.TraceElement
	var err error

	switch packetIn.Type {
	case PktNotSync:
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, "Trace Packet Synchronisation Lost"))
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		*pktDone = true
		return ocsd.RespFatalSysErr

	case PktIncompleteEOT, PktASync, PktIgnore:
		// ignore
	case PktCycleCount:
		pElem, err = d.getNextOpElem()
		if err == nil {
			pElem.SetType(ocsd.GenElemCycleCount)
			pElem.SetCycleCount(packetIn.CycleCount)
		}
	case PktTrigger:
		pElem, err = d.getNextOpElem()
		if err == nil {
			pElem.SetType(ocsd.GenElemEvent)
			pElem.Payload.TraceEvent.EvType = ocsd.EventTrigger
		}
	case PktBranchAddress:
		resp = d.processBranchAddr()
	case PktISyncCycle, PktISync:
		resp = d.processISync(packetIn.Type == PktISyncCycle, false)
	case PktPHdr:
		resp = d.processPHdr()
	case PktContextID:
		pElem, err = d.getNextOpElem()
		if err == nil {
			pElem.SetType(ocsd.GenElemPeContext)
			d.peContext.ContextID = packetIn.Context.CtxtID
			d.peContext.SetCtxtIDValid(true)
			pElem.Context = *d.peContext
		}
	case PktVMID:
		pElem, err = d.getNextOpElem()
		if err == nil {
			pElem.SetType(ocsd.GenElemPeContext)
			d.peContext.VMID = uint32(packetIn.Context.VMID)
			d.peContext.SetVMIDValid(true)
			pElem.Context = *d.peContext
		}
	case PktExceptionEntry:
		pElem, err = d.getNextOpElem()
		if err == nil {
			pElem.SetType(ocsd.GenElemException)
			pElem.SetExcepDataMarker(true)
		}
	case PktExceptionExit:
		pElem, err = d.getNextOpElem()
		if err == nil {
			pElem.SetType(ocsd.GenElemExceptionRet)
			d.pendExceptionReturn()
		}
	case PktTimestamp:
		pElem, err = d.getNextOpElem()
		if err == nil {
			pElem.SetType(ocsd.GenElemTimestamp)
			pElem.Timestamp = packetIn.Timestamp
		}
	case PktStoreFail, PktOOOData, PktOOOAddrPlc, PktNormData, PktDataSuppressed, PktValNotTraced, PktBadTraceMode:
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrHWCfgUnsupp, "Invalid packet type : Data Tracing decode not supported."))
		resp = ocsd.RespFatalInvalidData
	case PktBadSequence:
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, "Bad Packet sequence."))
		resp = ocsd.RespFatalInvalidData
	case PktReserved:
		fallthrough
	default:
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, "Reserved or unknown packet ID."))
		resp = ocsd.RespFatalInvalidData
	}

	if err != nil {
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		*pktDone = true
		return ocsd.RespFatalSysErr
	}

	if resp == ocsd.RespFatalInvalidData {
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		*pktDone = true
		return resp
	}

	if d.outputElemList.ElemToSend() {
		d.currState = sendPkts
	} else {
		d.currState = decodePkts
	}
	*pktDone = !d.outputElemList.ElemToSend()

	return resp
}

func (d *PktDecode) setNeedAddr(bNeedAddr bool) {
	d.bNeedAddr = bNeedAddr
	d.bSentUnknown = false
}

func (d *PktDecode) processISync(withCC bool, firstSync bool) ocsd.DatapathResp {
	onMap := []ocsd.TraceOnReason{ocsd.TraceOnNormal, ocsd.TraceOnNormal, ocsd.TraceOnOverflow, ocsd.TraceOnExDebug}

	packetIn := d.CurrPacketIn
	ctxtUpdate := packetIn.Context.UpdatedC || packetIn.Context.UpdatedV || packetIn.Context.Updated

	pElem, err := d.getNextOpElem()
	if err != nil {
		d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
		d.unsyncInfo = common.UnsyncBadPacket
		d.resetDecoder()
		return ocsd.RespFatalSysErr
	}

	if firstSync || packetIn.ISyncInfo.Reason != ocsd.ISyncPeriodic {
		pElem.SetType(ocsd.GenElemTraceOn)
		if int(packetIn.ISyncInfo.Reason) < len(onMap) {
			pElem.Payload.TraceOnReason = onMap[packetIn.ISyncInfo.Reason]
		}
		pElem, err = d.getNextOpElem()
		if err != nil {
			d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
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

		pElem.SetType(ocsd.GenElemPeContext)
		pElem.Context = *d.peContext
		pElem.ISA = packetIn.CurrISA
		d.codeFollower.SetISA(packetIn.CurrISA)

		if packetIn.ISyncInfo.HasCycleCount {
			pElem.SetCycleCount(packetIn.CycleCount)
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
		d.currState = sendPkts
	} else {
		d.currState = decodePkts
	}

	return ocsd.RespCont
}

func (d *PktDecode) processBranchAddr() ocsd.DatapathResp {
	packetIn := d.CurrPacketIn
	bUpdatePEContext := false

	if packetIn.Exception.Cancel {
		d.outputElemList.CancelPendElem()
	} else {
		d.outputElemList.CommitAllPendElem()
	}

	d.iAddr = packetIn.Addr
	d.setNeedAddr(false)

	if packetIn.Exception.Present {
		if packetIn.Context.UpdatedC || packetIn.Context.UpdatedV || packetIn.Context.Updated {
			if packetIn.Context.UpdatedC && d.peContext.ContextID != packetIn.Context.CtxtID {
				d.peContext.ContextID = packetIn.Context.CtxtID
				d.peContext.SetCtxtIDValid(true)
				bUpdatePEContext = true
			}
			if packetIn.Context.UpdatedV && d.peContext.VMID != uint32(packetIn.Context.VMID) {
				d.peContext.VMID = uint32(packetIn.Context.VMID)
				d.peContext.SetVMIDValid(true)
				bUpdatePEContext = true
			}
			if packetIn.Context.Updated {
				sec := ocsd.SecSecure
				if packetIn.Context.CurrNS {
					sec = ocsd.SecNonsecure
				}
				if sec != d.peContext.SecurityLevel {
					d.peContext.SecurityLevel = sec
					bUpdatePEContext = true
				}

				el := ocsd.ELUnknown
				if packetIn.Context.CurrHyp {
					el = ocsd.EL2
				}
				if el != d.peContext.ExceptionLevel {
					d.peContext.ExceptionLevel = el
					d.peContext.SetELValid(true)
					bUpdatePEContext = true
				}
			}
		}

		d.codeFollower.SetISA(packetIn.CurrISA)

		if bUpdatePEContext {
			pElem, err := d.getNextOpElem()
			if err != nil {
				d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
				d.unsyncInfo = common.UnsyncBadPacket
				d.resetDecoder()
				return ocsd.RespFatalSysErr
			}
			pElem.SetType(ocsd.GenElemPeContext)
			pElem.Context = *d.peContext
		}

		if packetIn.Exception.Number != 0 {
			pElem, err := d.getNextOpElem()
			if err != nil {
				d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
				d.unsyncInfo = common.UnsyncBadPacket
				d.resetDecoder()
				return ocsd.RespFatalSysErr
			}
			pElem.SetType(ocsd.GenElemException)
			pElem.Payload.ExceptionNum = uint32(packetIn.Exception.Number)
		}

		if d.outputElemList.ElemToSend() {
			d.currState = sendPkts
		} else {
			d.currState = decodePkts
		}
	}

	return ocsd.RespCont
}

func (d *PktDecode) pendExceptionReturn() {
	pendElem := 1
	if d.Config.CoreProf != ocsd.ProfileCortexM {
		nElem := d.outputElemList.GetNumElem()
		if nElem > 1 {
			if d.outputElemList.GetElemType(nElem-2) == ocsd.GenElemInstrRange {
				pendElem = 2
			}
		}
	}
	d.outputElemList.PendLastNElem(pendElem)
}

// processPHdr uses the etmv3Atoms struct pattern natively in Go inline since it doesn't need external exposure.
func (d *PktDecode) processPHdr() ocsd.DatapathResp {
	packetIn := d.CurrPacketIn
	isa := d.codeFollower.GetInstrInfo().Isa

	// Mimicking etmv3Atoms behaviors
	atomsNum := packetIn.Atom.Num
	enBits := packetIn.Atom.EnBits

	isCCPacket := d.Config.IsCycleAcc()

	getAtomCC := func() uint32 {
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

	getRemainCC := func() uint32 {
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

	memSpace := ocsd.MemSpaceN
	if d.peContext.SecurityLevel == ocsd.SecSecure {
		memSpace = ocsd.MemSpaceS
	}
	var pElem *ocsd.TraceElement
	var err error

	d.codeFollower.SetMemSpace(memSpace)

	for {
		if d.bNeedAddr {
			if !d.bSentUnknown || d.Config.IsCycleAcc() {
				pElem, err := d.getNextOpElem()
				if err != nil {
					d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
					d.unsyncInfo = common.UnsyncBadPacket
					d.resetDecoder()
					return ocsd.RespFatalSysErr
				}
				if d.bSentUnknown || atomsNum == 0 {
					pElem.SetType(ocsd.GenElemCycleCount)
				} else {
					pElem.SetType(ocsd.GenElemAddrUnknown)
				}
				if d.Config.IsCycleAcc() {
					pElem.SetCycleCount(getRemainCC())
				}
				d.bSentUnknown = true
			}
			atomsNum = 0 // clear all
		} else {
			if atomsNum > 0 {
				val := ocsd.AtomN
				if (enBits & 0x1) == 1 {
					val = ocsd.AtomE
				}

				// Follow instructions for this atom
				errCF := d.codeFollower.FollowSingleAtom(ocsd.VAddr(d.iAddr), val)
				if errCF != ocsd.OK && errCF != ocsd.ErrMemNacc {
					d.LogError(common.NewErrorMsg(ocsd.ErrSevError, errCF, "Error following atom"))
					return ocsd.RespFatalSysErr
				}

				if d.codeFollower.GetNumInstructs() > 0 {
					pElem, err = d.getNextOpElem()
					if err != nil {
						d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
						return ocsd.RespFatalSysErr
					}
					pElem.SetType(ocsd.GenElemInstrRange)
					pElem.StAddr = d.codeFollower.RangeSt()
					pElem.EnAddr = d.codeFollower.RangeEn()
					pElem.Payload.NumInstrRange = d.codeFollower.GetNumInstructs()

					instrInfo := d.codeFollower.GetInstrInfo()
					pElem.SetLastInstrExec(val == ocsd.AtomE)
					pElem.LastIType = instrInfo.Type
					pElem.LastISubtype = instrInfo.SubType
					pElem.SetLastInstrSz(instrInfo.InstrSize)
					pElem.SetLastInstrCond(instrInfo.IsConditional != 0)
					pElem.ISA = isa

					if d.Config.IsCycleAcc() {
						pElem.SetCycleCount(getAtomCC())
					}

					d.iAddr = uint64(d.codeFollower.GetNextAddr())
					isa = instrInfo.NextIsa

					if !d.codeFollower.HasNextAddr() {
						d.setNeedAddr(true)
					}
				}

				if errCF == ocsd.ErrMemNacc {
					pElem, err = d.getNextOpElem()
					if err != nil {
						d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
						return ocsd.RespFatalSysErr
					}
					pElem.SetType(ocsd.GenElemAddrNacc)
					pElem.StAddr = d.codeFollower.GetNextAddr()
					pElem.Payload.ExceptionNum = uint32(memSpace)
					d.setNeedAddr(true)
					d.codeFollower.ClearError()
				}
			} else if d.Config.IsCycleAcc() {
				// CC only packet (atomsNum == 0)
				pElem, err := d.getNextOpElem()
				if err != nil {
					d.LogError(common.NewErrorMsg(ocsd.ErrSevError, err.(*common.Error).Code, err.Error()))
					return ocsd.RespFatalSysErr
				}
				pElem.SetType(ocsd.GenElemCycleCount)
				pElem.SetCycleCount(getRemainCC())
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

	numElem := d.outputElemList.GetNumElem()
	if numElem >= 1 {
		if d.outputElemList.GetElemType(numElem-1) == ocsd.GenElemInstrRange {
			d.outputElemList.PendLastNElem(1)
		}
	}

	if d.outputElemList.ElemToSend() {
		d.currState = sendPkts
	} else {
		d.currState = decodePkts
	}

	return ocsd.RespCont
}

// DecoderManager is the registry factory for ETMv3 decoders
type DecoderManager struct {
}

func NewDecoderManager() *DecoderManager {
	return &DecoderManager{}
}

func (m *DecoderManager) CreatePktProc(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	proc := NewPktProc(instID)
	proc.SetProtocolConfig(cfg)
	return proc
}

func (m *DecoderManager) CreatePktDecode(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	dec := NewPktDecode(instID)
	dec.SetProtocolConfig(cfg)
	return dec
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	procAny := m.CreatePktProc(instID, config)
	if procAny == nil {
		return nil, nil, ocsd.ErrInvalidParamType
	}
	decAny := m.CreatePktDecode(instID, config)
	if decAny == nil {
		return nil, nil, ocsd.ErrInvalidParamType
	}
	proc := procAny.(*PktProc)
	dec := decAny.(*PktDecode)
	proc.PktOutI.ReplaceFirst(dec)
	return proc, dec, ocsd.OK
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolETMV3
}
