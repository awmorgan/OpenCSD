package ptm

import (
	"fmt"

	"opencsd/internal/common"
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

type atoms struct {
	atom      ocsd.PktAtom
	rootIndex ocsd.TrcIndex
}

func (a *atoms) init(atom ocsd.PktAtom, rootIndex ocsd.TrcIndex) {
	a.atom = atom
	a.rootIndex = rootIndex
}

func (a *atoms) getCurrAtomVal() ocsd.AtmVal {
	if (a.atom.EnBits & 0x1) != 0 {
		return ocsd.AtomE
	}
	return ocsd.AtomN
}

func (a *atoms) numAtoms() int {
	return int(a.atom.Num)
}

func (a *atoms) pktIndex() ocsd.TrcIndex {
	return a.rootIndex
}

func (a *atoms) clearAtom() {
	if a.atom.Num > 0 {
		a.atom.Num--
		a.atom.EnBits >>= 1
	}
}

func (a *atoms) clearAll() {
	a.atom.Num = 0
}

type PktDecode struct {
	common.PktDecodeBase[Packet, Config]

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

	atoms       atoms
	returnStack common.AddrReturnStack
	outputElem  ocsd.TraceElement
}

func NewPktDecode(instIDNum int) *PktDecode {
	d := &PktDecode{}
	d.InitPktDecodeBase(fmt.Sprintf("%s_%d", "DCD_PTM", instIDNum))

	d.FnProcessPacket = d.processPacket
	d.FnOnEOT = d.onEOT
	d.FnOnReset = d.onReset
	d.FnOnFlush = d.onFlush
	d.FnOnProtocolConfig = d.onProtocolConfig
	d.FnGetTraceID = d.getCoreSightTraceID

	d.initDecoder()
	return d
}

func (d *PktDecode) getCoreSightTraceID() uint8 {
	return d.csID
}

func (d *PktDecode) initDecoder() {
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

	d.instrInfo.Isa = ocsd.ISAUnknown
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

func (d *PktDecode) onProtocolConfig() ocsd.Err {
	if d.Config == nil {
		return ocsd.ErrNotInit
	}

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
	return ocsd.OK
}

func (d *PktDecode) onEOT() ocsd.DatapathResp {
	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	return d.OutputTraceElement(&d.outputElem)
}

func (d *PktDecode) onReset() ocsd.DatapathResp {
	d.unsyncInfo = common.UnsyncResetDecoder
	d.resetDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) onFlush() ocsd.DatapathResp {
	return d.contProcess()
}

func (d *PktDecode) processPacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	bPktDone := false

	for !bPktDone {
		switch d.currState {
		case decodeNoSync:
			d.outputElem.SetType(ocsd.GenElemNoSync)
			d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncInfo(d.unsyncInfo))
			resp = d.OutputTraceElement(&d.outputElem)
			if d.CurrPacketIn.Type == PktASync {
				d.currState = decodeWaitISync
			} else {
				d.currState = decodeWaitSync
			}
			bPktDone = true

		case decodeWaitSync:
			if d.CurrPacketIn.Type == PktASync {
				d.currState = decodeWaitISync
			}
			bPktDone = true

		case decodeWaitISync:
			if d.CurrPacketIn.Type == PktISync {
				d.currState = decodePkts
			} else {
				bPktDone = true
			}

		case decodePkts:
			resp = d.decodePacket()
			bPktDone = true

		default:
			bPktDone = true
		}
	}
	return resp
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
		resp = d.OutputTraceElement(&d.outputElem)
	case PktASync, PktIgnore:
		// ignore
	case PktISync:
		resp = d.processIsync()
	case PktBranchAddress:
		resp = d.processBranch()
	case PktTrigger:
		d.outputElem.SetType(ocsd.GenElemEvent)
		d.outputElem.SetEvent(ocsd.EventTrigger, 0)
		resp = d.OutputTraceElement(&d.outputElem)
	case PktWPointUpdate:
		resp = d.processWPUpdate()
	case PktContextID:
		bUpdate := true
		if d.peContext.CtxtIDValid() && d.peContext.ContextID == pkt.Context.CtxtID {
			bUpdate = false
		}
		if bUpdate {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.SetCtxtIDValid(true)
			d.outputElem.SetType(ocsd.GenElemPeContext)
			d.outputElem.SetContext(d.peContext)
			resp = d.OutputTraceElement(&d.outputElem)
		}
	case PktVMID:
		bUpdate := true
		if d.peContext.VMIDValid() && d.peContext.VMID == uint32(pkt.Context.VMID) {
			bUpdate = false
		}
		if bUpdate {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.SetVMIDValid(true)
			d.outputElem.SetType(ocsd.GenElemPeContext)
			d.outputElem.SetContext(d.peContext)
			resp = d.OutputTraceElement(&d.outputElem)
		}
	case PktAtom:
		if d.currPeState.valid {
			d.atoms.init(pkt.Atom, d.IndexCurrPkt)
			resp = d.processAtom()
		}
	case PktTimestamp:
		d.outputElem.SetType(ocsd.GenElemTimestamp)
		d.outputElem.Timestamp = pkt.Timestamp
		if pkt.CCValid {
			d.outputElem.SetCycleCount(pkt.CycleCount)
		}
		resp = d.OutputTraceElement(&d.outputElem)
	case PktExceptionRet:
		d.outputElem.SetType(ocsd.GenElemExceptionRet)
		resp = d.OutputTraceElement(&d.outputElem)
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
			resp = d.OutputTraceElement(&d.outputElem)
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
		resp = d.OutputTraceElement(&d.outputElem)
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
			d.outputElem.SetExcepRetAddr(false)
			if d.currPeState.valid {
				d.outputElem.SetExcepRetAddr(true)
				d.outputElem.EnAddr = d.currPeState.instrAddr
			}
			if pkt.CCValid {
				d.outputElem.SetCycleCount(pkt.CycleCount)
			}
			resp = d.OutputTraceElement(&d.outputElem)
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
		d.outputElem.StAddr = d.naccAddr
		if d.peContext.SecurityLevel == ocsd.SecSecure {
			d.outputElem.SetExceptionNum(uint32(ocsd.MemSpaceEL1S))
		} else {
			d.outputElem.SetExceptionNum(uint32(ocsd.MemSpaceEL1N))
		}
		*resp = d.OutputTraceElementIdx(d.IndexCurrPkt, &d.outputElem)
		d.memNaccPending = false
	}
}

func (d *PktDecode) processAtomRange(A ocsd.AtmVal, pktMsg string, traceWPOp waypointTraceOp, nextAddrMatch ocsd.VAddr) ocsd.DatapathResp {
	resp := ocsd.RespCont
	bWPFound := false
	err := ocsd.OK

	d.instrInfo.InstrAddr = d.currPeState.instrAddr
	d.instrInfo.Isa = d.currPeState.isa

	d.outputElem.SetType(ocsd.GenElemInstrRange)

	err = d.traceInstrToWP(&bWPFound, traceWPOp, nextAddrMatch)
	if err != ocsd.OK {
		if err == ocsd.ErrUnsupportedISA {
			d.currPeState.valid = false
			d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevWarn, err, d.IndexCurrPkt, d.csID, fmt.Sprintf("Warning: unsupported instruction set processing %s packet.", pktMsg)))
			return ocsd.RespWarnCont
		}
		d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, err, d.IndexCurrPkt, d.csID, fmt.Sprintf("Error processing %s packet.", pktMsg)))
		return ocsd.RespFatalInvalidData
	}

	if bWPFound {
		nextAddr := d.instrInfo.InstrAddr

		switch d.instrInfo.Type {
		case ocsd.InstrBr:
			if A == ocsd.AtomE {
				d.instrInfo.InstrAddr = d.instrInfo.BranchAddr
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.Isa)
				}
			}
		case ocsd.InstrBrIndirect:
			if A == ocsd.AtomE {
				d.currPeState.valid = false
				if d.returnStack.IsActive() && d.CurrPacketIn.Type == PktAtom {
					var nextIsa ocsd.ISA
					d.instrInfo.InstrAddr = d.returnStack.Pop(&nextIsa)
					d.instrInfo.NextIsa = nextIsa

					if d.returnStack.Overflow() {
						d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrRetStackOverflow, d.IndexCurrPkt, d.csID, fmt.Sprintf("Return stack error processing %s packet.", pktMsg)))
						return ocsd.RespFatalInvalidData
					} else {
						d.currPeState.valid = true
					}
				}
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.Isa)
				}
			}
		}

		d.outputElem.SetLastInstrInfo(A == ocsd.AtomE, d.instrInfo.Type, d.instrInfo.SubType, d.instrInfo.InstrSize)
		d.outputElem.SetISA(d.currPeState.isa)
		if d.CurrPacketIn.CCValid {
			d.outputElem.SetCycleCount(d.CurrPacketIn.CycleCount)
		}
		d.outputElem.SetLastInstrCond(d.instrInfo.IsConditional != 0)
		resp = d.OutputTraceElementIdx(d.IndexCurrPkt, &d.outputElem)

		d.currPeState.instrAddr = d.instrInfo.InstrAddr
		d.currPeState.isa = d.instrInfo.NextIsa
	} else {
		d.currPeState.valid = false
		if d.outputElem.StAddr != d.outputElem.EnAddr {
			d.outputElem.SetLastInstrInfo(true, d.instrInfo.Type, d.instrInfo.SubType, d.instrInfo.InstrSize)
			d.outputElem.SetISA(d.currPeState.isa)
			d.outputElem.SetLastInstrCond(d.instrInfo.IsConditional != 0)
			resp = d.OutputTraceElementIdx(d.IndexCurrPkt, &d.outputElem)
		}
	}
	return resp
}

func (d *PktDecode) traceInstrToWP(bWPFound *bool, traceWPOp waypointTraceOp, nextAddrMatch ocsd.VAddr) ocsd.Err {
	err := ocsd.OK
	var bytesReq uint32
	var currOpAddress ocsd.VAddr

	memSpace := ocsd.MemSpaceEL1N
	if d.peContext.SecurityLevel == ocsd.SecSecure {
		memSpace = ocsd.MemSpaceEL1S
	}

	d.outputElem.StAddr = d.instrInfo.InstrAddr
	d.outputElem.EnAddr = d.instrInfo.InstrAddr
	d.outputElem.Payload.NumInstrRange = 0

	*bWPFound = false

	for !*bWPFound && !d.memNaccPending {
		bytesReq = 4
		currOpAddress = d.instrInfo.InstrAddr
		bytesRead, memData, errMem := d.AccessMemory(d.instrInfo.InstrAddr, memSpace, bytesReq)
		if errMem != ocsd.OK {
			err = errMem
			break
		}

		if bytesRead == 4 {
			opcode := uint32(memData[0]) | uint32(memData[1])<<8 | uint32(memData[2])<<16 | uint32(memData[3])<<24
			d.instrInfo.Opcode = opcode
			err = d.InstrDecodeCall(&d.instrInfo)
			if err != ocsd.OK {
				break
			}

			d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
			d.outputElem.EnAddr = d.instrInfo.InstrAddr
			d.outputElem.Payload.NumInstrRange++
			d.outputElem.LastIType = d.instrInfo.Type

			if traceWPOp != traceWaypoint {
				if traceWPOp == traceToAddrExcl {
					*bWPFound = d.outputElem.EnAddr == nextAddrMatch
				} else {
					*bWPFound = currOpAddress == nextAddrMatch
				}
			} else {
				*bWPFound = d.instrInfo.Type != ocsd.InstrOther
			}
		} else {
			d.memNaccPending = true
			d.naccAddr = d.instrInfo.InstrAddr
		}
	}
	return err
}
