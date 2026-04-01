package ptm

import (
	"errors"
	"fmt"

	"opencsd/internal/common"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
)

type decodeState int

const (
	decodeNoSync decodeState = iota
	decodeWaitSync
	decodeWaitISync
	decodePkts
	decodeContISync
	decodeContAtom
	decodeContWPUp
	decodeContBranch
)

type waypointTraceOp int

const (
	traceWaypoint waypointTraceOp = iota
	traceToAddrExcl
	traceToAddrIncl
)

type peAddrState struct {
	isa       ocsd.ISA
	instrAddr ocsd.VAddr
	valid     bool
}

type PtmAtoms struct {
	atom      ocsd.PktAtom
	rootIndex ocsd.TrcIndex
}

func (a *PtmAtoms) set(atom ocsd.PktAtom, rootIndex ocsd.TrcIndex) {
	a.atom = atom
	a.rootIndex = rootIndex
}

func (a *PtmAtoms) getCurrAtomVal() ocsd.AtmVal {
	if (a.atom.EnBits & 0x1) != 0 {
		return ocsd.AtomE
	}
	return ocsd.AtomN
}

func (a *PtmAtoms) numAtoms() int {
	return int(a.atom.Num)
}

func (a *PtmAtoms) pktIndex() ocsd.TrcIndex {
	return a.rootIndex
}

func (a *PtmAtoms) clearAtom() {
	if a.atom.Num > 0 {
		a.atom.Num--
		a.atom.EnBits >>= 1
	}
}

func (a *PtmAtoms) clearAll() {
	a.atom.Num = 0
}

type PktDecode struct {
	common.DecoderBase
	Config       *Config
	CurrPacketIn *Packet
	lastErr      error

	currState   decodeState
	unsyncInfo  common.UnsyncInfo
	peContext   ocsd.PEContext
	currPeState peAddrState
	needIsync   bool

	csID           uint8
	instrInfo      ocsd.InstrInfo
	memNaccPending bool
	naccAddr       ocsd.VAddr
	iSyncPeCtxt    bool

	atoms       PtmAtoms
	returnStack common.AddrReturnStack
	outputElem  ocsd.TraceElement
}

func NewPktDecode(cfg *Config, _ ocsd.Logger) *PktDecode {
	instIDNum := 0
	if cfg != nil {
		instIDNum = int(cfg.TraceID())
	}
	d := &PktDecode{
		DecoderBase: common.DecoderBase{
			Name: fmt.Sprintf("DCD_PTM_%d", instIDNum),
			UsesMemAccess: true,
			UsesIDecode:   true,
		},
	}
	d.configureDecoder()
	if cfg != nil {
		_ = d.SetProtocolConfig(cfg)
	}
	return d
}

// SetTraceElemOut satisfies dcdtree's traceElemSetterOwner interface.
func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) { d.TraceElemOut = out }

// SetMemAccess satisfies dcdtree's memAccSetterOwner interface.
func (d *PktDecode) SetMemAccess(mem common.TargetMemAccess) { d.MemAccess = mem }

// SetInstrDecode satisfies dcdtree's instrDecodeSetterOwner interface.
func (d *PktDecode) SetInstrDecode(dec common.InstrDecode) { d.InstrDecode = dec }

// SetNeedsMemAccess controls whether memory access is required for decode.
func (d *PktDecode) SetNeedsMemAccess(needs bool) { d.UsesMemAccess = needs }

// SetNeedsInstructionDecode controls whether instruction decode is required.
func (d *PktDecode) SetNeedsInstructionDecode(needs bool) { d.UsesIDecode = needs }

func (d *PktDecode) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *Packet) ocsd.DatapathResp {
	resp := ocsd.RespCont
	d.lastErr = nil

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

func (d *PktDecode) TraceID() uint8 {
	return d.csID
}

func (d *PktDecode) configureDecoder() {
	d.csID = 0
	d.instrInfo.PeType.Profile = ocsd.ProfileUnknown
	d.instrInfo.PeType.Arch = ocsd.ArchUnknown
	d.instrInfo.DsbDmbWaypoints = 0
	d.unsyncInfo = common.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *PktDecode) processStateIsCont() bool {
	return d.currState >= decodeContISync
}

func (d *PktDecode) resetDecoder() {
	d.currState = decodeNoSync
	d.needIsync = true

	d.instrInfo.ISA = ocsd.ISAUnknown
	d.memNaccPending = false

	d.peContext.SetCtxtIDValid(false)
	d.peContext.SetBits64(false)
	d.peContext.SetVMIDValid(false)
	d.peContext.ExceptionLevel = ocsd.ELUnknown
	d.peContext.SecurityLevel = ocsd.SecSecure
	d.peContext.SetELValid(false)

	d.currPeState.instrAddr = 0
	d.currPeState.isa = ocsd.ISAUnknown
	d.currPeState.valid = false

	d.atoms.clearAll()
	d.outputElem.Init()
}

func (d *PktDecode) SetProtocolConfig(config *Config) error {
	d.Config = config
	if d.Config == nil {
		return ocsd.ErrNotInit
	}
	d.ConfigInitOK = true

	d.csID = d.Config.TraceID()

	if d.Config.HasRetStack() {
		d.returnStack.SetActive(d.Config.EnaRetStack())
	}

	d.instrInfo.PeType.Profile = d.Config.CoreProf
	d.instrInfo.PeType.Arch = d.Config.ArchVer
	if d.Config.DmsbWayPt() {
		d.instrInfo.DsbDmbWaypoints = 1
	} else {
		d.instrInfo.DsbDmbWaypoints = 0
	}
	d.instrInfo.WfiWfeBranch = 0
	d.instrInfo.ThumbItConditions = 0
	d.instrInfo.TrackItBlock = 0
	return nil
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont

	for ocsd.DataRespIsCont(resp) && (d.processStateIsCont() || d.memNaccPending || d.atoms.numAtoms() > 0) {
		if d.processStateIsCont() {
			resp = d.contProcess()
			continue
		}

		if d.atoms.numAtoms() > 0 {
			if d.currPeState.valid {
				resp = d.processAtom()
			} else {
				d.lastErr = fmt.Errorf("%w: dropped atom packet(s) at EOT while PE state is invalid", ocsd.ErrBadPacketSeq)
				d.atoms.clearAll()
				resp = ocsd.RespWarnCont
			}
			continue
		}

		d.checkPendingNacc(&resp)
	}

	if !ocsd.DataRespIsCont(resp) {
		return resp
	}

	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	return d.OutputTraceElement(d.csID, &d.outputElem)
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.unsyncInfo = common.UnsyncResetDecoder
	d.resetDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	return d.contProcess()
}

func (d *PktDecode) ProcessPacket() ocsd.DatapathResp {
	var resp ocsd.DatapathResp
	for {
		var next decodeState
		var done bool
		switch d.currState {
		case decodeNoSync:
			next, resp, done = d.handleNoSync()
		case decodeWaitSync:
			next, resp, done = d.handleWaitSync()
		case decodeWaitISync:
			next, resp, done = d.handleWaitISync()
		case decodePkts:
			next, resp, done = decodePkts, d.decodePacket(), true
		default:
			return ocsd.RespCont
		}
		d.currState = next
		if done {
			return resp
		}
	}
}

func (d *PktDecode) handleNoSync() (decodeState, ocsd.DatapathResp, bool) {
	d.outputElem.SetType(ocsd.GenElemNoSync)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncInfo(d.unsyncInfo))
	resp := d.OutputTraceElement(d.csID, &d.outputElem)
	if d.CurrPacketIn.Type == PktASync {
		return decodeWaitISync, resp, true
	}
	return decodeWaitSync, resp, true
}

func (d *PktDecode) handleWaitSync() (decodeState, ocsd.DatapathResp, bool) {
	if d.CurrPacketIn.Type == PktASync {
		return decodeWaitISync, ocsd.RespCont, true
	}
	return decodeWaitSync, ocsd.RespCont, true
}

func (d *PktDecode) handleWaitISync() (decodeState, ocsd.DatapathResp, bool) {
	if d.CurrPacketIn.Type == PktISync {
		return decodePkts, ocsd.RespCont, false // continue to decodePkts
	}
	return decodeWaitISync, ocsd.RespCont, true
}

func (d *PktDecode) contProcess() ocsd.DatapathResp {
	resp := ocsd.RespCont

	switch d.currState {
	case decodeContISync:
		resp = d.processIsync()
	case decodeContAtom:
		resp = d.processAtom()
	case decodeContWPUp:
		resp = d.processWPUpdate()
	case decodeContBranch:
		resp = d.processBranch()
	}

	if ocsd.DataRespIsCont(resp) && d.processStateIsCont() {
		d.currState = decodePkts
	}
	return resp
}

func (d *PktDecode) decodePacket() ocsd.DatapathResp {
	resp := ocsd.RespCont

	pkt := d.CurrPacketIn

	switch pkt.Type {
	case PktNotSync, PktIncompleteEOT, PktNoError:
		// ignore
	case PktBadSequence, PktReserved:
		d.currState = decodeWaitSync
		d.needIsync = true
		d.outputElem.SetType(ocsd.GenElemNoSync)
		resp = d.OutputTraceElement(d.csID, &d.outputElem)
	case PktASync, PktIgnore:
		// ignore
	case PktISync:
		resp = d.processIsync()
	case PktBranchAddress:
		resp = d.processBranch()
	case PktTrigger:
		d.outputElem.SetType(ocsd.GenElemEvent)
		d.outputElem.SetEvent(ocsd.EventTrigger, 0)
		resp = d.OutputTraceElement(d.csID, &d.outputElem)
	case PktWPointUpdate:
		resp = d.processWPUpdate()
	case PktContextID:
		update := true
		if d.peContext.CtxtIDValid() && d.peContext.ContextID == pkt.Context.CtxtID {
			update = false
		}
		if update {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.SetCtxtIDValid(true)
			d.outputElem.SetType(ocsd.GenElemPeContext)
			d.outputElem.SetContext(d.peContext)
			resp = d.OutputTraceElement(d.csID, &d.outputElem)
		}
	case PktVMID:
		update := true
		if d.peContext.VMIDValid() && d.peContext.VMID == uint32(pkt.Context.VMID) {
			update = false
		}
		if update {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.SetVMIDValid(true)
			d.outputElem.SetType(ocsd.GenElemPeContext)
			d.outputElem.SetContext(d.peContext)
			resp = d.OutputTraceElement(d.csID, &d.outputElem)
		}
	case PktAtom:
		if d.currPeState.valid {
			d.atoms.set(pkt.Atom, d.IndexCurrPkt)
			resp = d.processAtom()
		} else {
			d.lastErr = fmt.Errorf("%w: dropped atom packet while PE state is invalid; waiting for branch address or I-Sync", ocsd.ErrBadPacketSeq)
			resp = ocsd.RespWarnCont
		}
	case PktTimestamp:
		d.outputElem.SetType(ocsd.GenElemTimestamp)
		d.outputElem.Timestamp = pkt.Timestamp
		if pkt.CCValid {
			d.outputElem.SetCycleCount(pkt.CycleCount)
		}
		resp = d.OutputTraceElement(d.csID, &d.outputElem)
	case PktExceptionRet:
		d.outputElem.SetType(ocsd.GenElemExceptionRet)
		resp = d.OutputTraceElement(d.csID, &d.outputElem)
	}
	return resp
}

func (d *PktDecode) processIsync() ocsd.DatapathResp {
	resp := ocsd.RespCont

	pkt := d.CurrPacketIn

	if d.currState == decodePkts {
		d.currPeState.instrAddr = pkt.AddrVal
		d.currPeState.isa = pkt.CurrISA
		d.currPeState.valid = true

		d.iSyncPeCtxt = pkt.CurrISA != pkt.PrevISA
		if pkt.Context.UpdatedC {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.SetCtxtIDValid(true)
			d.iSyncPeCtxt = true
		}

		if pkt.Context.UpdatedV {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.SetVMIDValid(true)
			d.iSyncPeCtxt = true
		}
		if pkt.Context.CurrNS {
			d.peContext.SecurityLevel = ocsd.SecNonsecure
		} else {
			d.peContext.SecurityLevel = ocsd.SecSecure
		}

		if d.needIsync || pkt.ISyncReason != ocsd.ISyncPeriodic {
			d.outputElem.SetType(ocsd.GenElemTraceOn)
			d.outputElem.SetTraceOnReason(ocsd.TraceOnNormal)
			if pkt.ISyncReason == ocsd.ISyncTraceRestartAfterOverflow {
				d.outputElem.SetTraceOnReason(ocsd.TraceOnOverflow)
			} else if pkt.ISyncReason == ocsd.ISyncDebugExit {
				d.outputElem.SetTraceOnReason(ocsd.TraceOnExDebug)
			}
			if pkt.CCValid {
				d.outputElem.SetCycleCount(pkt.CycleCount)
			}
			resp = d.OutputTraceElement(d.csID, &d.outputElem)
		} else {
			d.iSyncPeCtxt = false
		}
		d.needIsync = false
		d.returnStack.Flush()
	}

	if d.iSyncPeCtxt && ocsd.DataRespIsCont(resp) {
		d.outputElem.SetType(ocsd.GenElemPeContext)
		d.outputElem.SetContext(d.peContext)
		d.outputElem.SetISA(d.currPeState.isa)
		resp = d.OutputTraceElement(d.csID, &d.outputElem)
		d.iSyncPeCtxt = false
	}

	if ocsd.DataRespIsWait(resp) && d.iSyncPeCtxt {
		d.currState = decodeContISync
	}

	return resp
}

func (d *PktDecode) processBranch() ocsd.DatapathResp {
	resp := ocsd.RespCont

	pkt := d.CurrPacketIn

	if d.currState == decodePkts {
		if pkt.Exception.Present {
			d.outputElem.SetType(ocsd.GenElemException)
			d.outputElem.SetExceptionNum(uint32(pkt.Exception.Number))
			d.outputElem.ExceptionRetAddr = false
			if d.currPeState.valid {
				d.outputElem.ExceptionRetAddr = true
				d.outputElem.EndAddr = d.currPeState.instrAddr
			}
			if pkt.CCValid {
				d.outputElem.SetCycleCount(pkt.CycleCount)
			}
			resp = d.OutputTraceElement(d.csID, &d.outputElem)
		} else {
			if d.currPeState.valid {
				resp = d.processAtomRange(ocsd.AtomE, "BranchAddr", traceWaypoint, 0)
			}
		}

		d.currPeState.isa = pkt.CurrISA
		d.currPeState.instrAddr = pkt.AddrVal
		d.currPeState.valid = true
	}

	d.checkPendingNacc(&resp)

	if ocsd.DataRespIsWait(resp) && d.memNaccPending {
		d.currState = decodeContBranch
	}
	return resp
}

func (d *PktDecode) processWPUpdate() ocsd.DatapathResp {
	resp := ocsd.RespCont

	if d.currPeState.valid {
		resp = d.processAtomRange(ocsd.AtomE, "WP update", traceToAddrIncl, d.CurrPacketIn.AddrVal)
	}

	d.checkPendingNacc(&resp)

	if ocsd.DataRespIsWait(resp) && d.memNaccPending {
		d.currState = decodeContWPUp
	}
	return resp
}

func (d *PktDecode) processAtom() ocsd.DatapathResp {
	resp := ocsd.RespCont

	for d.atoms.numAtoms() > 0 && d.currPeState.valid && ocsd.DataRespIsCont(resp) {
		resp = d.processAtomRange(d.atoms.getCurrAtomVal(), "atom", traceWaypoint, 0)
		if !d.currPeState.valid {
			d.atoms.clearAll()
		} else {
			d.atoms.clearAtom()
		}
	}

	d.checkPendingNacc(&resp)

	if ocsd.DataRespIsWait(resp) && (d.memNaccPending || d.atoms.numAtoms() > 0) {
		d.currState = decodeContAtom
	}

	return resp
}

func (d *PktDecode) checkPendingNacc(resp *ocsd.DatapathResp) {
	if d.memNaccPending && ocsd.DataRespIsCont(*resp) {
		d.outputElem.SetType(ocsd.GenElemAddrNacc)
		d.outputElem.StartAddr = d.naccAddr
		if d.peContext.SecurityLevel == ocsd.SecSecure {
			d.outputElem.SetExceptionNum(uint32(ocsd.MemSpaceS))
		} else {
			d.outputElem.SetExceptionNum(uint32(ocsd.MemSpaceN))
		}
		*resp = d.OutputTraceElementIdx(d.IndexCurrPkt, d.csID, &d.outputElem)
		d.memNaccPending = false
	}
}

func (d *PktDecode) processAtomRange(A ocsd.AtmVal, pktMsg string, traceWPOp waypointTraceOp, nextAddrMatch ocsd.VAddr) ocsd.DatapathResp {
	resp := ocsd.RespCont

	wpFound := false
	var err error

	d.instrInfo.InstrAddr = d.currPeState.instrAddr
	d.instrInfo.ISA = d.currPeState.isa

	d.outputElem.SetType(ocsd.GenElemInstrRange)

	wpFound, err = d.traceInstrToWP(traceWPOp, nextAddrMatch)
	if err != nil {
		if errors.Is(err, ocsd.ErrUnsupportedISA) {
			d.currPeState.valid = false
			d.lastErr = fmt.Errorf("%w: unsupported instruction set processing %s packet", err, pktMsg)
			return ocsd.RespWarnCont
		}
		d.lastErr = fmt.Errorf("%w: error processing %s packet", err, pktMsg)
		return ocsd.RespFatalInvalidData
	}

	if wpFound {
		nextAddr := d.instrInfo.InstrAddr

		switch d.instrInfo.Type {
		case ocsd.InstrBr:
			if A == ocsd.AtomE {
				d.instrInfo.InstrAddr = d.instrInfo.BranchAddr
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.ISA)
				}
			}
		case ocsd.InstrBrIndirect:
			if A == ocsd.AtomE {
				d.currPeState.valid = false
				if d.returnStack.IsActive() && d.CurrPacketIn.Type == PktAtom && (d.instrInfo.Subtype == ocsd.SInstrV8Ret || d.instrInfo.Subtype == ocsd.SInstrV7ImpliedRet) {
					var nextIsa ocsd.ISA
					d.instrInfo.InstrAddr = d.returnStack.Pop(&nextIsa)
					d.instrInfo.NextISA = nextIsa

					if d.returnStack.Overflow() {
						d.lastErr = fmt.Errorf("%w: return stack error processing %s packet", ocsd.ErrRetStackOverflow, pktMsg)
						return ocsd.RespFatalInvalidData
					} else {
						d.currPeState.valid = true
					}
				}
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.ISA)
				}
			}
		}

		d.outputElem.SetLastInstrInfo(A == ocsd.AtomE, d.instrInfo.Type, d.instrInfo.Subtype, d.instrInfo.InstrSize)
		d.outputElem.SetISA(d.currPeState.isa)
		if d.CurrPacketIn.CCValid {
			d.outputElem.SetCycleCount(d.CurrPacketIn.CycleCount)
		}
		d.outputElem.LastInstrCond = d.instrInfo.IsConditional != 0
		resp = d.OutputTraceElementIdx(d.IndexCurrPkt, d.csID, &d.outputElem)

		d.currPeState.instrAddr = d.instrInfo.InstrAddr
		d.currPeState.isa = d.instrInfo.NextISA
	} else {
		d.currPeState.valid = false
		if d.outputElem.StartAddr != d.outputElem.EndAddr {
			d.outputElem.SetLastInstrInfo(true, d.instrInfo.Type, d.instrInfo.Subtype, d.instrInfo.InstrSize)
			d.outputElem.SetISA(d.currPeState.isa)
			d.outputElem.LastInstrCond = d.instrInfo.IsConditional != 0
			resp = d.OutputTraceElementIdx(d.IndexCurrPkt, d.csID, &d.outputElem)
		}
	}
	return resp
}

func (d *PktDecode) traceInstrToWP(traceWPOp waypointTraceOp, nextAddrMatch ocsd.VAddr) (wpFound bool, err error) {
	err = nil
	var bytesReq uint32
	var currOpAddress ocsd.VAddr

	memSpace := ocsd.MemSpaceEL1N
	if d.peContext.SecurityLevel == ocsd.SecSecure {
		memSpace = ocsd.MemSpaceEL1S
	}

	d.outputElem.StartAddr = d.instrInfo.InstrAddr
	d.outputElem.EndAddr = d.instrInfo.InstrAddr
	d.outputElem.Payload.NumInstrRange = 0

	wpFound = false

	for !wpFound && !d.memNaccPending {
		bytesReq = 4
		currOpAddress = d.instrInfo.InstrAddr
		bytesRead, memData, errMem := d.AccessMemory(d.instrInfo.InstrAddr, d.csID, memSpace, bytesReq)
		if errMem != nil {
			if errors.Is(errMem, memacc.ErrNoAccessor) {
				d.memNaccPending = true
				d.naccAddr = d.instrInfo.InstrAddr
				break
			}
			err = errMem
			break
		}

		canDecode := bytesRead == 4
		if !canDecode && d.instrInfo.ISA == ocsd.ISAThumb2 && bytesRead >= 2 {
			instHW := uint16(memData[0]) | uint16(memData[1])<<8
			if !idec.IsWideThumb(instHW) {
				canDecode = true
			}
		}

		if canDecode {
			opcode := uint32(0)
			if bytesRead >= 1 {
				opcode |= uint32(memData[0])
			}
			if bytesRead >= 2 {
				opcode |= uint32(memData[1]) << 8
			}
			if bytesRead >= 3 {
				opcode |= uint32(memData[2]) << 16
			}
			if bytesRead >= 4 {
				opcode |= uint32(memData[3]) << 24
			}
			d.instrInfo.Opcode = opcode
			err = d.InstrDecodeCall(&d.instrInfo)
			if err != nil {
				break
			}

			d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
			d.outputElem.EndAddr = d.instrInfo.InstrAddr
			d.outputElem.Payload.NumInstrRange++
			d.outputElem.LastInstrType = d.instrInfo.Type

			if traceWPOp != traceWaypoint {
				if traceWPOp == traceToAddrExcl {
					wpFound = d.outputElem.EndAddr == nextAddrMatch
				} else {
					wpFound = currOpAddress == nextAddrMatch
				}
			} else {
				wpFound = d.instrInfo.Type != ocsd.InstrOther
			}
		} else {
			d.memNaccPending = true
			d.naccAddr = d.instrInfo.InstrAddr
		}
	}
	return wpFound, err
}
