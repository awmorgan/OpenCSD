package etmv4

import (
	"fmt"

	"opencsd/internal/common"
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

type decodeState int

const (
	noSync decodeState = iota
	waitSync
	waitISync
	decodePkts
	resolveElem
	commitElem
)

// P0 element types for execution speculation
type p0ElemType int

const (
	p0Unknown p0ElemType = iota
	p0Atom
	p0Addr
	p0Ctxt
	p0TrcOn
	p0Excep
	p0ExcepRet
	p0Event
	p0TS
	p0CC
	p0TSCC
	p0Marker
	p0Q
	p0Overflow
	p0FuncRet
	p0SrcAddr
	p0TransTraceInit
	p0TransStart
	p0TransCommit
	p0TransFail
	p0ITE
	p0UnseenUncommitted
	p0TInfo
)

// p0Elem represents a stacked element for speculation resolution
type p0Elem struct {
	p0Type    p0ElemType
	isP0      bool // true if genuine P0 - commit / cancellable
	rootPkt   PktType
	rootIndex ocsd.TrcIndex

	// Fields for different types
	addrVal  ocsd.VAddr
	addrIS   uint8
	context  Context
	atom     ocsd.PktAtom
	excepNum uint16
	prevSame bool
	params   [4]uint32
	marker   ocsd.TraceMarkerPayload
	ite      ocsd.TraceSWIte
	qCount   int
	qHasAddr bool
}

func (e *p0Elem) isEmpty() bool {
	if e.p0Type == p0Atom {
		return e.atom.Num == 0
	}
	return false
}

func (e *p0Elem) commitOldest() ocsd.AtmVal {
	val := ocsd.AtomN
	if (e.atom.EnBits & 0x1) != 0 {
		val = ocsd.AtomE
	}
	e.atom.Num--
	e.atom.EnBits >>= 1
	return val
}

func (e *p0Elem) cancelNewest(nCancel int) int {
	nRemove := nCancel
	if nCancel > int(e.atom.Num) {
		nRemove = int(e.atom.Num)
	}
	e.atom.Num -= uint8(nRemove)
	return nRemove
}

func (e *p0Elem) mispredictNewest() {
	mask := uint32(1) << (e.atom.Num - 1)
	if (e.atom.EnBits & mask) != 0 {
		e.atom.EnBits &^= mask
	} else {
		e.atom.EnBits |= mask
	}
}

type elemRes struct {
	P0Commit   int
	P0Cancel   int
	Mispredict bool
	Discard    bool
}

// Ensure PktDecode implements interfaces.TrcDataIn
// And also we extend PktDecodeBase
type PktDecode struct {
	common.PktDecodeBase[TracePacket, Config]

	currState decodeState
	config    *Config

	// Element states
	p0Stack     []*p0Elem
	poppedElems []*p0Elem // kept to avoid excessive allocations
	elemRes     elemRes
	outElem     common.GenElemStack

	// Address and Context State
	lastIS           uint8
	needCtxt         bool
	needAddr         bool
	extPendExcepAddr bool
	elemPendingAddr  bool
	isSecure         bool
	is64bit          bool
	peContext        ocsd.PEContext
	prevOverflow     bool
	memSpace         ocsd.MemSpaceAcc

	// Intra packet state
	timestamp   uint64
	ccThreshold uint32

	// Trace info state
	maxSpecDepth  int
	currSpecDepth int

	// Instr info
	instrInfo ocsd.InstrInfo

	// Return stack, etc...
	returnStack common.AddrReturnStack
}

// NewPktDecode creates a new ETMv4/ETE trace decoder
func NewPktDecode(instIDNum int) *PktDecode {
	d := &PktDecode{}
	d.InitPktDecodeBase(fmt.Sprintf("%s_%d", "DCD_ETMV4", instIDNum))

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
	if d.config != nil {
		return d.config.TraceID()
	}
	return 0
}

func (d *PktDecode) initDecoder() {
	// Not needed yet depending on PktDecodeBase
	// d.ResetDecoderBase()
	d.currState = noSync
	if d.config != nil {
		d.maxSpecDepth = int(d.config.MaxSpecDepth())
	} else {
		d.maxSpecDepth = 0
	}
	d.currSpecDepth = 0
	d.needCtxt = true
	d.needAddr = true
	d.extPendExcepAddr = false
	d.elemPendingAddr = false
	d.prevOverflow = false
	d.timestamp = 0
	d.ccThreshold = 0
	d.clearElemRes()
	d.p0Stack = nil
	d.poppedElems = nil
	d.outElem = *common.NewGenElemStack()
	d.returnStack = *common.NewAddrReturnStack()
}

func (d *PktDecode) onProtocolConfig() ocsd.Err {
	d.config = d.Config
	if d.config == nil {
		return ocsd.ErrInvalidParamVal
	}
	// Extract basic config elements
	d.maxSpecDepth = int(d.config.MaxSpecDepth())
	// d.InitDecoderCore()
	d.initDecoder()
	return ocsd.OK
}

func (d *PktDecode) onEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if d.currState == resolveElem {
		resp = d.resolveElements()
	}
	return resp
}

func (d *PktDecode) onReset() ocsd.DatapathResp {
	d.initDecoder()
	return ocsd.RespCont
}

func (d *PktDecode) onFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (d *PktDecode) processPacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	var err ocsd.Err

	pkt := d.CurrPacketIn

	switch d.currState {
	case noSync:
		if pkt.Type == PktAsync {
			d.currState = waitISync
			err = d.outElem.ResetElemStack()
			if err == ocsd.OK {
				d.outElem.AddElemType(d.IndexCurrPkt, ocsd.GenElemNoSync)
				resp = d.outElem.SendElements()
			}
		}

	case waitISync:
		if pkt.Type == PktTraceInfo {
			d.doTraceInfoPacket()
		} else if pkt.Type == PktAddrCtxtL_32IS0 || pkt.Type == PktAddrCtxtL_32IS1 ||
			pkt.Type == PktAddrCtxtL_64IS0 || pkt.Type == PktAddrCtxtL_64IS1 {

			d.currState = decodePkts
			err = d.outElem.ResetElemStack()
			if err == ocsd.OK {
				d.outElem.AddElemType(d.IndexCurrPkt, ocsd.GenElemTraceOn)
				d.outElem.GetCurrElem().Payload.TraceOnReason = ocsd.TraceOnNormal
				if d.prevOverflow {
					d.outElem.GetCurrElem().Payload.TraceOnReason = ocsd.TraceOnOverflow
					d.prevOverflow = false
				}
				resp = d.outElem.SendElements()
			}
			if resp == ocsd.RespCont {
				err = d.decodePacket()
			}
		} else if pkt.Type == PktAsync {
			// keep waiting
		} else if pkt.Type == PktOverflow {
			d.prevOverflow = true
		} else if pkt.Type == PktTraceOn {
			d.prevOverflow = false
		}

	case decodePkts:
		err = d.decodePacket()

	case resolveElem:
		resp = d.resolveElements()
		if resp == ocsd.RespCont && d.currState == resolveElem {
			d.currState = decodePkts
		}
	}

	if err != ocsd.OK {
		if d.currState == noSync {
			resp = ocsd.RespErrCont
		} else {
			resp = ocsd.RespFatalInvalidData
		}
	}
	return resp
}

func (d *PktDecode) clearElemRes() {
	d.elemRes.P0Commit = 0
	d.elemRes.P0Cancel = 0
	d.elemRes.Mispredict = false
	d.elemRes.Discard = false
}

func (d *PktDecode) isElemForRes() bool {
	return d.elemRes.P0Commit != 0 || d.elemRes.P0Cancel != 0 || d.elemRes.Mispredict || d.elemRes.Discard
}

func (d *PktDecode) resolveElements() ocsd.DatapathResp {
	resp := ocsd.RespCont
	complete := false

	for !complete {
		if d.outElem.NumElemToSend() > 0 {
			resp = d.outElem.SendElements()
		} else if d.isElemForRes() {
			err := ocsd.OK
			if d.elemRes.P0Commit != 0 {
				err = d.commitElements()
			}

			if d.elemRes.P0Commit == 0 {
				if err == ocsd.OK && d.elemRes.P0Cancel != 0 {
					err = d.cancelElements()
				}
				if err == ocsd.OK && d.elemRes.Mispredict {
					err = d.mispredictAtom()
				}
				if err == ocsd.OK && d.elemRes.Discard {
					err = d.discardElements()
				}
			}

			if err != ocsd.OK {
				if d.currState == noSync {
					resp = ocsd.RespErrCont
				} else {
					resp = ocsd.RespFatalInvalidData
				}
			}
		}

		if resp != ocsd.RespCont && resp != ocsd.RespWait {
			// Wait or Error - break out
			break
		}
		if (resp == ocsd.RespWait) && (d.outElem.NumElemToSend() > 0) {
			break
		}

		complete = d.outElem.NumElemToSend() == 0 && !d.isElemForRes()
		if complete {
			if d.currState == resolveElem {
				d.currState = decodePkts
			}
		}
	}
	return resp
}

func (d *PktDecode) decodePacket() ocsd.Err {
	err := ocsd.OK
	pkt := d.CurrPacketIn
	isAddr := false

	switch pkt.Type {
	case PktAsync, PktIgnore:
		// Do nothing
	case PktTraceInfo:
		d.pushP0ElemParam(p0TInfo, false, pkt.Type, d.IndexCurrPkt, nil)
	case PktTraceOn:
		d.pushP0ElemParam(p0TrcOn, false, pkt.Type, d.IndexCurrPkt, nil)
	case PktAtomF1, PktAtomF2, PktAtomF3, PktAtomF4, PktAtomF5, PktAtomF6:
		d.pushP0ElemAtom(pkt.Type, d.IndexCurrPkt, pkt.Atom)
		d.currSpecDepth += int(pkt.Atom.Num)
	case PktCtxt:
		d.pushP0ElemContext(pkt.Type, d.IndexCurrPkt, pkt.Context, d.lastIS)
	case PktAddrMatch:
		addr := pkt.VAddr
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemAddr(pkt.Type, d.IndexCurrPkt, addr, d.lastIS, false)
		isAddr = true
	case PktAddrCtxtL_64IS0, PktAddrCtxtL_64IS1, PktAddrCtxtL_32IS0, PktAddrCtxtL_32IS1:
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemContext(pkt.Type, d.IndexCurrPkt, pkt.Context, d.lastIS)
		fallthrough
	case PktAddrL_32IS0, PktAddrL_32IS1, PktAddrL_64IS0, PktAddrL_64IS1, PktAddrS_IS0, PktAddrS_IS1:
		addr := pkt.VAddr
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemAddr(pkt.Type, d.IndexCurrPkt, addr, d.lastIS, false)
		isAddr = true
	case ETE_PktSrcAddrMatch, ETE_PktSrcAddrS_IS0, ETE_PktSrcAddrS_IS1, ETE_PktSrcAddrL_32IS0, ETE_PktSrcAddrL_32IS1, ETE_PktSrcAddrL_64IS0, ETE_PktSrcAddrL_64IS1:
		addr := pkt.VAddr
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemAddr(pkt.Type, d.IndexCurrPkt, addr, d.lastIS, true)
		d.currSpecDepth++
	case PktExcept:
		d.pushP0ElemExcept(pkt.Type, d.IndexCurrPkt, pkt.ExceptionInfo.AddrInterp == 0x2, pkt.ExceptionInfo.ExceptionType)
		d.elemPendingAddr = true
	case PktExceptRtn:
		bV7MProfile := (d.config.ArchVer == ocsd.ArchV7) && (d.config.CoreProf == ocsd.ProfileCortexM)
		d.pushP0ElemParam(p0ExcepRet, bV7MProfile, pkt.Type, d.IndexCurrPkt, nil)
		if bV7MProfile {
			d.currSpecDepth++
		}
	}

	if isAddr && d.elemPendingAddr {
		d.currSpecDepth++
		d.elemPendingAddr = false
	}

	return err
}

func (d *PktDecode) commitElements() ocsd.Err {
	err := ocsd.OK
	bPopElem := true
	numCommitReq := d.elemRes.P0Commit
	var errIdx ocsd.TrcIndex
	contextFlush := false

	err = d.outElem.ResetElemStack()

	for d.elemRes.P0Commit > 0 && err == ocsd.OK && !contextFlush {
		if len(d.p0Stack) > 0 {
			pElem := d.p0Stack[0] // get oldest element
			errIdx = pElem.rootIndex
			bPopElem = true

			switch pElem.p0Type {
			case p0TrcOn:
				d.nextRangeCheckClear()
				err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemTraceOn)
				if err == ocsd.OK {
					reason := ocsd.TraceOnNormal
					if d.prevOverflow {
						reason = ocsd.TraceOnOverflow
					}
					d.outElem.GetCurrElem().Payload.TraceOnReason = reason
					d.prevOverflow = false
					d.returnStack.Flush()
				}

			case p0Addr:
				d.returnStack.ClearPopPending()
				if d.returnStack.IsTInfoWaitAddr() {
					// equivalent to is_t_info_wait_addr / clear_t_info_wait_addr
					d.returnStack.ClearTInfoWaitAddr()
				}
				d.setInstrInfoInAddrISA(pElem.addrVal, pElem.addrIS)
				d.needAddr = false

			case p0Ctxt:
				if pElem.context.Updated {
					err = d.outElem.AddElem(pElem.rootIndex)
					if err == ocsd.OK {
						d.updateContext(pElem, d.outElem.GetCurrElem())
						contextFlush = true
						d.InvalidateMemAccCache()
					}
				}

			case p0Event, p0TS, p0CC, p0TSCC:
				err = d.processTSCCEventElem(pElem)

			case p0Marker:
				err = d.processMarkerElem(pElem)

			case p0Atom:
				for !pElem.isEmpty() && d.elemRes.P0Commit > 0 && err == ocsd.OK {
					atom := pElem.commitOldest()

					if err = d.returnStackPop(); err != ocsd.OK {
						break
					}

					if !d.needCtxt && !d.needAddr {
						if err = d.processAtom(atom, pElem); err != ocsd.OK {
							break
						}
					}
					if d.elemRes.P0Commit > 0 {
						d.elemRes.P0Commit--
					}
				}
				if !pElem.isEmpty() {
					bPopElem = false
				}

			case p0Excep:
				if err = d.returnStackPop(); err != ocsd.OK {
					break
				}
				d.nextRangeCheckClear()
				err = d.processException(pElem)
				d.elemRes.P0Commit--

			case p0ExcepRet:
				d.nextRangeCheckClear()
				err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemExceptionRet)
				if err == ocsd.OK {
					if pElem.isP0 {
						d.elemRes.P0Commit--
					}
				}

			case p0FuncRet:
				if pElem.isP0 {
					d.elemRes.P0Commit--
				}

			case p0SrcAddr:
				d.nextRangeCheckClear()
				err = d.processSourceAddress(pElem)
				d.elemRes.P0Commit--

			case p0Q:
				d.nextRangeCheckClear()
				err = d.processQElement(pElem)
				d.elemRes.P0Commit--

			case p0TransStart:
				if d.config.CommTransP0() {
					d.elemRes.P0Commit--
				}
				fallthrough
			case p0TransCommit, p0TransFail, p0TransTraceInit:
				d.nextRangeCheckClear()
				err = d.processTransElem(pElem)

			case p0ITE:
				err = d.processITEElem(pElem)

			case p0UnseenUncommitted:
				d.elemRes.P0Commit--

			case p0TInfo:
				d.returnStack.SetTInfoWaitAddr() // tinfo_wait_addr
				d.returnStack.Flush()
			}

			if bPopElem {
				e := d.p0Stack[0]
				d.poppedElems = append(d.poppedElems, e)
				d.p0Stack = d.p0Stack[1:] // pop_front
			}
		} else {
			err = d.handlePacketSeqErr(ocsd.ErrCommitPktOverrun, errIdx, "Not enough elements to commit")
		}
	}

	d.currSpecDepth -= (numCommitReq - d.elemRes.P0Commit)
	return err
}

func (d *PktDecode) setInstrInfoInAddrISA(addr ocsd.VAddr, isa uint8) {
	d.instrInfo.InstrAddr = addr
	d.instrInfo.Isa = d.calcISA(d.is64bit, isa)
}

func (d *PktDecode) nextRangeCheckClear() {
	// TODO stub
}

func (d *PktDecode) getCurrMemSpace() ocsd.MemSpaceAcc {
	sec := d.peContext.SecurityLevel
	el := d.peContext.ExceptionLevel

	if sec == ocsd.SecRoot {
		return ocsd.MemSpaceRoot
	} else if sec == ocsd.SecRealm {
		if el == ocsd.EL1 || el == ocsd.EL0 {
			return ocsd.MemSpaceEL1R
		}
		if el == ocsd.EL2 {
			return ocsd.MemSpaceEL2R
		}
		return ocsd.MemSpaceR
	} else if sec == ocsd.SecSecure {
		if el == ocsd.EL3 {
			return ocsd.MemSpaceEL3
		}
		if el == ocsd.EL2 {
			return ocsd.MemSpaceEL2S
		}
		if el == ocsd.EL1 || el == ocsd.EL0 {
			return ocsd.MemSpaceEL1S
		}
		return ocsd.MemSpaceS // unknown EL
	}

	if el == ocsd.EL2 {
		return ocsd.MemSpaceEL2
	}
	if el == ocsd.EL1 || el == ocsd.EL0 {
		return ocsd.MemSpaceEL1N
	}
	return ocsd.MemSpaceN
}

func (d *PktDecode) updateContext(pElem *p0Elem, elem *ocsd.TraceElement) {
	ctx := pElem.context
	elem.SetType(ocsd.GenElemPeContext)

	d.is64bit = ctx.SF
	elem.Context.SetBits64(ctx.SF)
	d.isSecure = !ctx.NS
	if ctx.NSE {
		if ctx.NS {
			elem.Context.SecurityLevel = ocsd.SecRealm
		} else {
			elem.Context.SecurityLevel = ocsd.SecRoot
		}
	} else {
		if ctx.NS {
			elem.Context.SecurityLevel = ocsd.SecNonsecure
		} else {
			elem.Context.SecurityLevel = ocsd.SecSecure
		}
	}
	elem.Context.ExceptionLevel = ocsd.ExLevel(ctx.EL)
	elem.Context.SetELValid(true)

	if ctx.UpdatedC {
		elem.Context.SetCtxtIDValid(true)
		elem.Context.ContextID = ctx.CtxtID
	}
	if ctx.UpdatedV {
		elem.Context.SetVMIDValid(true)
		elem.Context.VMID = ctx.VMID
	}

	elem.ISA = d.calcISA(d.is64bit, pElem.addrIS)
	d.instrInfo.Isa = elem.ISA
	d.peContext = elem.Context // keep local copy updated
	d.needCtxt = false
}

func (d *PktDecode) returnStackPop() ocsd.Err {
	err := ocsd.OK
	if d.returnStack.PopPending() {
		isa := new(ocsd.ISA)
		popAddr := d.returnStack.Pop(isa)
		overflow := d.returnStack.Overflow()
		if overflow {
			err = ocsd.ErrRetStackOverflow
			err = d.handlePacketSeqErr(err, ocsd.BadTrcIndex, "Trace Return Stack Overflow.")
		} else {
			d.instrInfo.InstrAddr = popAddr
			d.instrInfo.Isa = *isa
			d.needAddr = false
		}
	}
	return err
}

func (d *PktDecode) processTSCCEventElem(pElem *p0Elem) ocsd.Err {
	bPermitTS := !d.config.EteHasTSMarker() || true // m_ete_first_ts_marker omitted for now
	var err ocsd.Err = ocsd.OK

	switch pElem.p0Type {
	case p0Event:
		err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemEvent)
		if err == ocsd.OK {
			d.outElem.GetCurrElem().Payload.TraceEvent.EvType = ocsd.EventNumbered
			d.outElem.GetCurrElem().Payload.TraceEvent.EvNumber = uint16(pElem.params[0])
		}
	case p0TS:
		if bPermitTS {
			err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemTimestamp)
			if err == ocsd.OK {
				d.outElem.GetCurrElem().Timestamp = uint64(pElem.params[0]) | (uint64(pElem.params[1]) << 32)
			}
		}
	case p0CC:
		err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemCycleCount)
		if err == ocsd.OK {
			d.outElem.GetCurrElem().CycleCount = pElem.params[0]
		}
	case p0TSCC:
		if bPermitTS {
			err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemTimestamp)
			if err == ocsd.OK {
				d.outElem.GetCurrElem().Timestamp = uint64(pElem.params[0]) | (uint64(pElem.params[1]) << 32)
				d.outElem.GetCurrElem().CycleCount = pElem.params[2]
			}
		}
	}
	return err
}

func (d *PktDecode) processMarkerElem(pElem *p0Elem) ocsd.Err {
	err := d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemSyncMarker)
	if err == ocsd.OK {
		d.outElem.GetCurrElem().Payload.SyncMarker = pElem.marker
	}
	return err
}

func (d *PktDecode) processTransElem(pElem *p0Elem) ocsd.Err {
	err := d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemMemTrans)
	if err == ocsd.OK {
		tt := ocsd.MemTransFail - ocsd.TraceMemtrans(p0TransFail-pElem.p0Type)
		d.outElem.GetCurrElem().Payload.MemTrans = tt
	}
	return err
}

func (d *PktDecode) processITEElem(pElem *p0Elem) ocsd.Err {
	err := d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemInstrumentation)
	if err == ocsd.OK {
		d.outElem.GetCurrElem().Payload.SWIte = pElem.ite
	}
	return err
}

type wpRes int

const (
	wpNotFound wpRes = iota
	wpFound
	wpNacc
)

type instrRange struct {
	stAddr   ocsd.VAddr
	enAddr   ocsd.VAddr
	numInstr uint32
}

func (d *PktDecode) setElemTraceRange(elem *ocsd.TraceElement, addrRange instrRange, executed bool, index ocsd.TrcIndex) {
	d.setElemTraceRangeInstr(elem, addrRange, executed, index, &d.instrInfo)
}

func (d *PktDecode) setElemTraceRangeInstr(elem *ocsd.TraceElement, addrRange instrRange, executed bool, index ocsd.TrcIndex, instr *ocsd.InstrInfo) {
	elem.SetType(ocsd.GenElemInstrRange)
	elem.SetLastInstrInfo(executed, instr.Type, instr.SubType, instr.InstrSize)
	elem.ISA = instr.Isa
	elem.SetLastInstrCond(instr.IsConditional != 0)
	elem.StAddr = addrRange.stAddr
	elem.EnAddr = addrRange.enAddr
	elem.Payload.NumInstrRange = addrRange.numInstr
	if executed {
		instr.Isa = instr.NextIsa
	}
}

func (d *PktDecode) traceInstrToWP(rangeOut *instrRange, res *wpRes, traceToAddrNext bool, nextAddrMatch ocsd.VAddr) ocsd.Err {
	var err ocsd.Err
	rangeOut.stAddr = d.instrInfo.InstrAddr
	rangeOut.enAddr = d.instrInfo.InstrAddr
	rangeOut.numInstr = 0
	*res = wpNotFound

	for *res == wpNotFound {
		bytesReq := uint32(4)
		currMemSpace := d.getCurrMemSpace()
		bytesRead, memData, errMem := d.AccessMemory(d.instrInfo.InstrAddr, currMemSpace, bytesReq)
		if errMem != ocsd.OK {
			return errMem
		}

		if bytesRead == 4 {
			opcode := uint32(memData[0]) | uint32(memData[1])<<8 | uint32(memData[2])<<16 | uint32(memData[3])<<24
			d.instrInfo.Opcode = opcode
			err = d.InstrDecodeCall(&d.instrInfo)
			if err != ocsd.OK {
				break
			}

			d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
			rangeOut.numInstr++

			if traceToAddrNext {
				if d.instrInfo.InstrAddr == nextAddrMatch {
					*res = wpFound
				}
			} else if d.instrInfo.Type != ocsd.InstrOther {
				*res = wpFound
			}
		} else {
			*res = wpNacc
		}
	}
	rangeOut.enAddr = d.instrInfo.InstrAddr
	return err
}

func (d *PktDecode) processAtom(atom ocsd.AtmVal, pElem *p0Elem) ocsd.Err {
	var WPRes wpRes
	var addrRange instrRange
	ETE_ERET := false

	err := d.outElem.AddElem(pElem.rootIndex)
	if err != ocsd.OK {
		return err
	}

	err = d.traceInstrToWP(&addrRange, &WPRes, false, 0)
	if err != ocsd.OK {
		if err == ocsd.ErrUnsupportedISA {
			d.needAddr = true
			d.needCtxt = true
			d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevWarn, err, pElem.rootIndex, d.getCoreSightTraceID(), "Warning: unsupported instruction set processing atom packet."))
			return ocsd.OK
		}
		return d.handlePacketSeqErr(err, pElem.rootIndex, "Error processing atom packet.")
	}

	if WPRes == wpFound {
		nextAddr := d.instrInfo.InstrAddr

		switch d.instrInfo.Type {
		case ocsd.InstrBr:
			if atom == ocsd.AtomE {
				d.instrInfo.InstrAddr = d.instrInfo.BranchAddr
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.Isa)
				}
			}
		case ocsd.InstrBrIndirect:
			if atom == ocsd.AtomE {
				d.needAddr = true
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.Isa)
				}
				d.returnStack.SetPopPending()
				if d.config.ArchVer >= ocsd.ArchV8 && d.instrInfo.SubType == ocsd.SInstrV8Eret {
					ETE_ERET = true // simulate ETE ERET
				}
			}
		}

		d.setElemTraceRange(d.outElem.GetCurrElem(), addrRange, atom == ocsd.AtomE, pElem.rootIndex)

		if ETE_ERET {
			err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemExceptionRet)
			if err != ocsd.OK {
				return err
			}
		}
	} else {
		d.needAddr = true

		if addrRange.stAddr != addrRange.enAddr {
			d.setElemTraceRange(d.outElem.GetCurrElem(), addrRange, true, pElem.rootIndex)
			if WPRes == wpNacc {
				err = d.outElem.AddElem(pElem.rootIndex)
			}
		}

		if WPRes == wpNacc && err == ocsd.OK {
			d.outElem.GetCurrElem().SetType(ocsd.GenElemAddrNacc)
			d.outElem.GetCurrElem().StAddr = d.instrInfo.InstrAddr

			currMemSpace := d.getCurrMemSpace()
			d.outElem.GetCurrElem().Payload.ExceptionNum = uint32(currMemSpace)
		}
	}
	return ocsd.OK
}

func (d *PktDecode) processException(pElem *p0Elem) ocsd.Err {
	var err ocsd.Err
	var pCtxtElem *p0Elem
	var pAddressElem *p0Elem

	pExceptElem := pElem
	excepPktIndex := pExceptElem.rootIndex
	branchTarget := pExceptElem.prevSame
	ETE_resetPkt := false // reset packet not supported yet

	var excepRetAddr ocsd.VAddr
	var WPRes wpRes
	bMTailChain := false

	idx := 1
	if !ETE_resetPkt {
		if idx < len(d.p0Stack) && d.p0Stack[idx].p0Type == p0Ctxt {
			pCtxtElem = d.p0Stack[idx]
			idx++
		}

		if idx >= len(d.p0Stack) || d.p0Stack[idx].p0Type != p0Addr {
			return d.handlePacketSeqErr(ocsd.ErrBadPacketSeq, d.IndexCurrPkt, "Address missing in exception packet.")
		}
		pAddressElem = d.p0Stack[idx]
		excepRetAddr = pAddressElem.addrVal

		if branchTarget {
			b64bit := d.instrInfo.Isa == ocsd.ISAAArch64
			if pCtxtElem != nil {
				b64bit = pCtxtElem.context.SF
			}
			d.instrInfo.InstrAddr = excepRetAddr
			if pAddressElem.addrIS == 0 {
				if b64bit {
					d.instrInfo.Isa = ocsd.ISAAArch64
				} else {
					d.instrInfo.Isa = ocsd.ISAArm
				}
			} else {
				d.instrInfo.Isa = ocsd.ISAThumb2
			}
			d.needAddr = false
		}
	}

	err = d.outElem.AddElem(excepPktIndex)
	if err != ocsd.OK {
		return err
	}

	if pCtxtElem != nil {
		d.updateContext(pCtxtElem, d.outElem.GetCurrElem())
		err = d.outElem.AddElem(excepPktIndex)
		if err != ocsd.OK {
			return err
		}
	}

	if !ETE_resetPkt {
		if d.config.CoreProf == ocsd.ProfileCortexM {
			bMTailChain = excepRetAddr == 0xFFFFFFFE
		}

		if d.instrInfo.InstrAddr < excepRetAddr && !bMTailChain {
			rangeOut := false
			var addrRange instrRange

			err = d.traceInstrToWP(&addrRange, &WPRes, true, excepRetAddr)
			if err != ocsd.OK {
				if err == ocsd.ErrUnsupportedISA {
					d.needAddr = true
					d.needCtxt = true
					d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevWarn, err, excepPktIndex, d.getCoreSightTraceID(), "Warning: unsupported instruction set processing exception packet."))
				} else {
					d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, err, excepPktIndex, d.getCoreSightTraceID(), "Error processing exception packet."))
				}
				return err
			}

			if WPRes == wpFound {
				d.setElemTraceRange(d.outElem.GetCurrElem(), addrRange, true, excepPktIndex)
				rangeOut = true
			} else {
				d.needAddr = true
				if addrRange.stAddr != addrRange.enAddr {
					d.setElemTraceRange(d.outElem.GetCurrElem(), addrRange, true, excepPktIndex)
					rangeOut = true
				}
			}

			if rangeOut {
				err = d.outElem.AddElem(excepPktIndex)
				if err != ocsd.OK {
					return err
				}
			}
		}

		if WPRes == wpNacc {
			d.outElem.GetCurrElem().SetType(ocsd.GenElemAddrNacc)
			d.outElem.GetCurrElem().StAddr = d.instrInfo.InstrAddr
			d.outElem.GetCurrElem().Payload.ExceptionNum = uint32(d.getCurrMemSpace())

			err = d.outElem.AddElem(excepPktIndex)
			if err != ocsd.OK {
				return err
			}
		}
	}

	d.outElem.GetCurrElem().SetType(ocsd.GenElemException)
	d.outElem.GetCurrElem().EnAddr = excepRetAddr
	d.outElem.GetCurrElem().SetExcepRetAddr(true)
	if bMTailChain {
		d.outElem.GetCurrElem().SetExcepRetAddr(false)
		d.outElem.GetCurrElem().SetExcepMTailChain(true)
	}
	d.outElem.GetCurrElem().SetExcepRetAddrBrTgt(branchTarget)
	d.outElem.GetCurrElem().Payload.ExceptionNum = uint32(pExceptElem.excepNum)

	// Remove processed elements from p0Stack
	// pElem (index 0) will be popped by the caller. So pop from 1 to idx
	if idx > 0 {
		for i := 1; i <= idx; i++ {
			d.poppedElems = append(d.poppedElems, d.p0Stack[i])
		}
		// Safe slice removal inside the struct pointer
		d.p0Stack = append(d.p0Stack[:1], d.p0Stack[idx+1:]...)
	}

	return err
}

func (d *PktDecode) processSourceAddress(pElem *p0Elem) ocsd.Err {
	var err ocsd.Err
	srcAddr := pElem.addrVal
	currAddr := d.instrInfo.InstrAddr
	var outRange instrRange
	bSplitRangeOnN := false

	bytesReq := uint32(4)
	bytesRead, memData, errMem := d.AccessMemory(srcAddr, d.getCurrMemSpace(), bytesReq)
	if errMem != ocsd.OK {
		d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, errMem, pElem.rootIndex, d.getCoreSightTraceID(), "Mem access error processing source address packet."))
		return errMem
	}

	if bytesRead != 4 {
		err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemAddrNacc)
		d.outElem.GetCurrElem().StAddr = srcAddr
		d.outElem.GetCurrElem().Payload.ExceptionNum = uint32(d.getCurrMemSpace())
		return err
	}

	opcode := uint32(memData[0]) | uint32(memData[1])<<8 | uint32(memData[2])<<16 | uint32(memData[3])<<24
	d.instrInfo.Opcode = opcode
	d.instrInfo.InstrAddr = srcAddr
	err = d.InstrDecodeCall(&d.instrInfo)
	if err != ocsd.OK {
		d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, err, pElem.rootIndex, d.getCoreSightTraceID(), "Instruction decode error processing source address packet."))
		return err
	}
	d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)

	outRange.numInstr = 1

	if d.needAddr || currAddr > srcAddr {
		d.needAddr = false
		outRange.stAddr = srcAddr
	} else {
		outRange.stAddr = currAddr
	}
	outRange.enAddr = d.instrInfo.InstrAddr

	if outRange.enAddr-outRange.stAddr > ocsd.VAddr(d.instrInfo.InstrSize) {
		if d.instrInfo.Isa != ocsd.ISAThumb2 && !bSplitRangeOnN {
			outRange.numInstr = uint32(outRange.enAddr-outRange.stAddr) / 4
		} else {
			instr := d.instrInfo
			instr.InstrAddr = outRange.stAddr
			outRange.numInstr = 0
			bMemAccErr := false

			for instr.InstrAddr < outRange.enAddr && !bMemAccErr {
				bytesReq = 4
				bytesRead, mData, eMem := d.AccessMemory(instr.InstrAddr, d.getCurrMemSpace(), bytesReq)
				if eMem != ocsd.OK {
					return eMem
				}

				if bytesRead == 4 {
					instr.Opcode = uint32(mData[0]) | uint32(mData[1])<<8 | uint32(mData[2])<<16 | uint32(mData[3])<<24
					eDec := d.InstrDecodeCall(&instr)
					if eDec != ocsd.OK {
						return eDec
					}
					instr.InstrAddr += ocsd.VAddr(instr.InstrSize)
					outRange.numInstr++
				} else {
					bMemAccErr = true
					err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemAddrNacc)
					if err != ocsd.OK {
						return err
					}
					d.outElem.GetCurrElem().StAddr = srcAddr
					d.outElem.GetCurrElem().Payload.ExceptionNum = uint32(d.getCurrMemSpace())
					outRange.numInstr = 1
					outRange.stAddr = srcAddr
					outRange.enAddr = d.instrInfo.InstrAddr
				}
			}
		}
	}

	switch d.instrInfo.Type {
	case ocsd.InstrBr:
		if d.instrInfo.IsLink != 0 {
			d.returnStack.Push(d.instrInfo.InstrAddr, d.instrInfo.Isa)
		}
		d.instrInfo.InstrAddr = d.instrInfo.BranchAddr

	case ocsd.InstrBrIndirect:
		d.needAddr = true
		if d.instrInfo.IsLink != 0 {
			d.returnStack.Push(d.instrInfo.InstrAddr, d.instrInfo.Isa)
		}
		d.returnStack.SetPopPending()
	}
	d.instrInfo.Isa = d.instrInfo.NextIsa

	d.outElem.AddElem(pElem.rootIndex)
	d.setElemTraceRange(d.outElem.GetCurrElem(), outRange, true, pElem.rootIndex)

	return err
}

func (d *PktDecode) processQElement(pElem *p0Elem) ocsd.Err {
	var err ocsd.Err
	var qAddr ocsd.VAddr
	var qIs uint8
	iCount := pElem.qCount

	if !pElem.qHasAddr {
		var pAddressElem *p0Elem
		var pCtxtElem *p0Elem

		idx := 1
		if idx < len(d.p0Stack) && d.p0Stack[idx].p0Type == p0Ctxt {
			pCtxtElem = d.p0Stack[idx]
			idx++
		}

		if idx >= len(d.p0Stack) || d.p0Stack[idx].p0Type != p0Addr {
			d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrBadPacketSeq, pElem.rootIndex, d.getCoreSightTraceID(), "Address missing in Q packet."))
			return ocsd.ErrBadPacketSeq
		}
		pAddressElem = d.p0Stack[idx]
		qAddr = pAddressElem.addrVal
		qIs = pAddressElem.addrIS

		for i := 1; i <= idx; i++ {
			d.poppedElems = append(d.poppedElems, d.p0Stack[i])
		}
		d.p0Stack = append(d.p0Stack[:1], d.p0Stack[idx+1:]...)

		if pCtxtElem != nil {
			d.p0Stack = append(d.p0Stack[:1], append([]*p0Elem{pCtxtElem}, d.p0Stack[1:]...)...)
		}
	} else {
		qAddr = pElem.addrVal
		qIs = pElem.addrIS
	}

	err = d.outElem.AddElem(pElem.rootIndex)
	if err != ocsd.OK {
		return err
	}

	var addrRange instrRange
	addrRange.stAddr = d.instrInfo.InstrAddr
	addrRange.enAddr = d.instrInfo.InstrAddr
	addrRange.numInstr = 0
	isBranch := false

	for i := 0; i < iCount; i++ {
		bytesReq := uint32(4)
		bytesRead, memData, errMem := d.AccessMemory(d.instrInfo.InstrAddr, d.getCurrMemSpace(), bytesReq)
		if errMem != ocsd.OK {
			break
		}

		if bytesRead == 4 {
			opcode := uint32(memData[0]) | uint32(memData[1])<<8 | uint32(memData[2])<<16 | uint32(memData[3])<<24
			d.instrInfo.Opcode = opcode
			eDec := d.InstrDecodeCall(&d.instrInfo)
			if eDec != ocsd.OK {
				break
			}

			d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
			addrRange.numInstr++

			isBranch = (d.instrInfo.Type == ocsd.InstrBr) || (d.instrInfo.Type == ocsd.InstrBrIndirect)
			if isBranch {
				break
			}
		} else {
			break
		}
	}

	if err == ocsd.OK {
		inCompleteRange := true
		if iCount > 0 && addrRange.numInstr == uint32(iCount) {
			if d.instrInfo.InstrAddr == qAddr || isBranch {
				inCompleteRange = false
				addrRange.enAddr = d.instrInfo.InstrAddr
				d.setElemTraceRange(d.outElem.GetCurrElem(), addrRange, true, pElem.rootIndex)
			}
		}

		if inCompleteRange {
			addrRange.enAddr = qAddr
			addrRange.numInstr = uint32(iCount)

			d.outElem.GetCurrElem().SetType(ocsd.GenElemIRangeNopath)
			d.outElem.GetCurrElem().StAddr = addrRange.stAddr
			d.outElem.GetCurrElem().EnAddr = addrRange.enAddr
			d.outElem.GetCurrElem().Payload.NumInstrRange = addrRange.numInstr
			d.outElem.GetCurrElem().ISA = d.calcISA(d.is64bit, qIs)
		}

		d.setInstrInfoInAddrISA(qAddr, qIs)
		d.needAddr = false
	} else {
		d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, err, pElem.rootIndex, d.getCoreSightTraceID(), "Error processing Q packet"))
	}

	return err
}

func (d *PktDecode) cancelElements() ocsd.Err {
	err := ocsd.OK
	p0StackDone := false
	temp := make([]*p0Elem, 0)
	numCancelReq := d.elemRes.P0Cancel

	for d.elemRes.P0Cancel > 0 {
		if !p0StackDone {
			if len(d.p0Stack) == 0 {
				p0StackDone = true
			} else {
				pElem := d.p0Stack[0]
				if pElem.isP0 {
					if pElem.p0Type == p0Atom {
						d.elemRes.P0Cancel -= pElem.cancelNewest(d.elemRes.P0Cancel)
						if pElem.isEmpty() {
							d.poppedElems = append(d.poppedElems, d.p0Stack[0])
							d.p0Stack = d.p0Stack[1:]
						}
					} else {
						d.elemRes.P0Cancel--
						d.poppedElems = append(d.poppedElems, d.p0Stack[0])
						d.p0Stack = d.p0Stack[1:]
					}
				} else {
					switch pElem.p0Type {
					case p0Event, p0TS, p0CC, p0TSCC, p0Marker, p0ITE:
						temp = append(temp, pElem)
						d.p0Stack = d.p0Stack[1:]
					default:
						d.poppedElems = append(d.poppedElems, d.p0Stack[0])
						d.p0Stack = d.p0Stack[1:]
					}
				}
				if len(d.p0Stack) == 0 {
					p0StackDone = true
				}
			}
		} else {
			err = ocsd.ErrCommitPktOverrun
			err = d.handlePacketSeqErr(err, d.IndexCurrPkt, "Not enough elements to cancel")
			d.elemRes.P0Cancel = 0
			break
		}
	}

	for i := len(temp) - 1; i >= 0; i-- {
		d.p0Stack = append([]*p0Elem{temp[i]}, d.p0Stack...)
	}

	d.currSpecDepth -= numCancelReq - d.elemRes.P0Cancel
	return err
}

func (d *PktDecode) mispredictAtom() ocsd.Err {
	err := ocsd.OK
	bFoundAtom := false
	bDone := false

	var newStack []*p0Elem
	for i := 0; i < len(d.p0Stack) && !bDone; i++ {
		pElem := d.p0Stack[i]
		if pElem.p0Type == p0Atom {
			pElem.mispredictNewest()
			bFoundAtom = true
			bDone = true
			newStack = append(newStack, pElem)
		} else if pElem.p0Type == p0Addr {
			// discard
			d.poppedElems = append(d.poppedElems, pElem)
		} else if pElem.p0Type == p0UnseenUncommitted {
			bDone = true
			bFoundAtom = true
			newStack = append(newStack, pElem)
		} else {
			newStack = append(newStack, pElem)
		}
	}
	if !bDone {
		d.p0Stack = newStack
	} else {
		d.p0Stack = append(newStack, d.p0Stack[len(newStack):]...)
	}

	if !bFoundAtom {
		err = d.handlePacketSeqErr(ocsd.ErrCommitPktOverrun, d.IndexCurrPkt, "Not found mispredict atom")
	}
	d.elemRes.Mispredict = false
	return err
}

func (d *PktDecode) discardElements() ocsd.Err {
	var err ocsd.Err = ocsd.OK

	for len(d.p0Stack) > 0 && err == ocsd.OK {
		pElem := d.p0Stack[len(d.p0Stack)-1] // back

		if pElem.p0Type == p0Marker {
			err = d.processMarkerElem(pElem)
		} else if pElem.p0Type == p0ITE {
			err = d.processITEElem(pElem)
		} else {
			err = d.processTSCCEventElem(pElem)
		}
		d.poppedElems = append(d.poppedElems, pElem)
		d.p0Stack = d.p0Stack[:len(d.p0Stack)-1]
	}

	d.clearElemRes()
	d.currSpecDepth = 0

	d.currState = noSync
	// m_unsync_eot_info handling etc...
	d.needCtxt = true
	d.needAddr = true
	d.elemPendingAddr = false
	return err
}

func (d *PktDecode) doTraceInfoPacket() {
	pkt := d.CurrPacketIn
	d.ccThreshold = pkt.CCThreshold
	d.currSpecDepth = int(pkt.CurrSpecDepth)

	// create unseen
	for i := 0; i < d.currSpecDepth; i++ {
		d.pushP0ElemParam(p0UnseenUncommitted, true, pkt.Type, d.IndexCurrPkt, nil)
	}

	d.pushP0ElemParam(p0TInfo, false, pkt.Type, d.IndexCurrPkt, nil)

	if pkt.TraceInfo.InTransState {
		d.pushP0ElemParam(p0TransTraceInit, false, pkt.Type, d.IndexCurrPkt, nil)
	}
}

func (d *PktDecode) handlePacketSeqErr(err ocsd.Err, idx ocsd.TrcIndex, reason string) ocsd.Err {
	d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, err, idx, d.getCoreSightTraceID(), reason))
	d.resetDecoderState()
	return err
}

func (d *PktDecode) handleBadImageError(idx ocsd.TrcIndex, reason string) ocsd.Err {
	d.LogError(common.NewErrorWithIdxChanMsg(ocsd.ErrSevError, ocsd.ErrBadDecodeImage, idx, d.getCoreSightTraceID(), reason))
	d.resetDecoderState()
	return ocsd.ErrBadDecodeImage
}

func (d *PktDecode) resetDecoderState() {
	d.initDecoder()
}

func (d *PktDecode) calcISA(is64bit bool, is uint8) ocsd.ISA {
	if is64bit {
		return ocsd.ISAAArch64
	}
	if is == 1 {
		return ocsd.ISAThumb2
	}
	return ocsd.ISAArm
}

// ========================
// P0 Stack manipulations
// ========================
func (d *PktDecode) allocP0Elem() *p0Elem {
	if len(d.poppedElems) > 0 {
		e := d.poppedElems[len(d.poppedElems)-1]
		d.poppedElems = d.poppedElems[:len(d.poppedElems)-1]
		*e = p0Elem{} // clear
		return e
	}
	return &p0Elem{}
}

func (d *PktDecode) pushP0ElemParam(p0Type p0ElemType, isP0 bool, rootPkt PktType, rootIndex ocsd.TrcIndex, params []uint32) {
	e := d.allocP0Elem()
	e.p0Type = p0Type
	e.isP0 = isP0
	e.rootPkt = rootPkt
	e.rootIndex = rootIndex
	for i, p := range params {
		if i < 4 {
			e.params[i] = p
		}
	}
	d.p0Stack = append(d.p0Stack, e)
}

func (d *PktDecode) pushP0ElemAtom(rootPkt PktType, rootIndex ocsd.TrcIndex, atom ocsd.PktAtom) {
	e := d.allocP0Elem()
	e.p0Type = p0Atom
	e.isP0 = true
	e.rootPkt = rootPkt
	e.rootIndex = rootIndex
	e.atom = atom
	d.p0Stack = append(d.p0Stack, e)
}

func (d *PktDecode) pushP0ElemContext(rootPkt PktType, rootIndex ocsd.TrcIndex, ctx Context, IS uint8) {
	e := d.allocP0Elem()
	e.p0Type = p0Ctxt
	e.isP0 = false
	e.rootPkt = rootPkt
	e.rootIndex = rootIndex
	e.context = ctx
	e.addrIS = IS
	d.p0Stack = append(d.p0Stack, e)
}

func (d *PktDecode) pushP0ElemAddr(rootPkt PktType, rootIndex ocsd.TrcIndex, addr ocsd.VAddr, IS uint8, isSrc bool) {
	e := d.allocP0Elem()
	if isSrc {
		e.p0Type = p0SrcAddr
	} else {
		e.p0Type = p0Addr
	}
	e.isP0 = false
	e.rootPkt = rootPkt
	e.rootIndex = rootIndex
	e.addrVal = addr
	e.addrIS = IS
	d.p0Stack = append(d.p0Stack, e)
}

func (d *PktDecode) pushP0ElemExcept(rootPkt PktType, rootIndex ocsd.TrcIndex, prevSame bool, excepNum uint16) {
	e := d.allocP0Elem()
	e.p0Type = p0Excep
	e.isP0 = true
	e.rootPkt = rootPkt
	e.rootIndex = rootIndex
	e.prevSame = prevSame
	e.excepNum = excepNum
	d.p0Stack = append(d.p0Stack, e)
}

// DecoderManager is the registry factory for ETMv4 decoders
type DecoderManager struct{}

func NewDecoderManager() *DecoderManager {
	return &DecoderManager{}
}

func (m *DecoderManager) CreatePktProc(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	proc := NewProcessor(cfg)
	return proc
}

func (m *DecoderManager) CreatePktDecode(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	decoder := NewPktDecode(instID)
	if decoder.SetProtocolConfig(cfg) != ocsd.OK {
		return nil
	}
	return decoder
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	procAny := m.CreatePktProc(instID, config)
	if procAny == nil {
		return nil, nil, ocsd.ErrInvalidParamVal
	}
	decAny := m.CreatePktDecode(instID, config)
	if decAny == nil {
		return nil, nil, ocsd.ErrInvalidParamVal
	}
	proc := procAny.(*Processor)
	decoder := decAny.(*PktDecode)
	proc.SetPktOut(decoder)
	return proc, decoder, ocsd.OK
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolETMV4I
}
