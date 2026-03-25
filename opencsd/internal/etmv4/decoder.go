package etmv4

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"opencsd/internal/common"

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
	nRemove := min(nCancel, int(e.atom.Num))
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

// PktDecode decodes ETMv4 trace packets into generic trace elements.
// It uses composition (Base DecoderBase) instead of inheritance.
type PktDecode struct {
	Base common.DecoderBase

	Config       *Config
	CurrPacketIn *TracePacket

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

	unsyncEOTInfo    ocsd.UnsyncInfo
	unsyncPktIdx     ocsd.TrcIndex
	eteFirstTSMarker bool

	instrRangeLimit uint32
	aa64BadOpcode   bool

	// Expected start address for the next continuous range (C++ m_next_range_check).
	nextRangeCheck struct {
		nextStAddr ocsd.VAddr
		valid      bool
	}
}

// SetTraceElemOut satisfies dcdtree's traceElemSetterOwner interface.
func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) { d.Base.TraceElemOut = out }

// SetMemAccess satisfies dcdtree's memAccSetterOwner interface.
func (d *PktDecode) SetMemAccess(mem common.TargetMemAccess) { d.Base.MemAccess = mem }

// SetInstrDecode satisfies dcdtree's instrDecodeSetterOwner interface.
func (d *PktDecode) SetInstrDecode(dec common.InstrDecode) { d.Base.InstrDecode = dec }

// ConfigureComponentOpMode delegates to Base for snapshot-test type assertions.
func (d *PktDecode) ConfigureComponentOpMode(flags uint32) error {
	return d.Base.ConfigureComponentOpMode(flags)
}

// ComponentOpMode delegates to Base for snapshot-test type assertions.
func (d *PktDecode) ComponentOpMode() uint32 { return d.Base.ComponentOpMode() }

// SupportedOpModes delegates to Base for snapshot-test type assertions.
func (d *PktDecode) SupportedOpModes() uint32 { return d.Base.SupportedOpModes() }

func NewPktDecode(cfg *Config, logger ocsd.Logger) *PktDecode {
	d := &PktDecode{}
	instIDNum := 0
	if cfg != nil {
		instIDNum = int(cfg.TraceID())
	}
	d.Base.Init(fmt.Sprintf("%s_%d", "DCD_ETMV4", instIDNum), logger)
	d.Base.ConfigureSupportedOpModes(ocsd.OpflgPktdecCommon | ocsd.OpflgPktdecSrcAddrNAtoms | ocsd.OpflgPktdecAA64OpcodeChk)
	if cfg != nil {
		_ = d.SetProtocolConfig(cfg)
	} else {
		d.configureDecoder()
	}
	return d
}

func (d *PktDecode) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *TracePacket) ocsd.DatapathResp {
	resp := ocsd.RespCont

	if reason := d.Base.DecodeNotReadyReason(); reason != "" {
		d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: %s", ocsd.ErrNotInit, reason))
		return ocsd.RespFatalNotInit
	}

	switch op {
	case ocsd.OpData:
		if pktIn == nil {
			d.Base.LogError(ocsd.ErrSevError, ocsd.ErrInvalidParamVal)
			resp = ocsd.RespFatalInvalidParam
		} else {
			d.CurrPacketIn = pktIn
			d.Base.IndexCurrPkt = indexSOP
			resp = d.ProcessPacket()
		}
	case ocsd.OpEOT:
		resp = d.OnEOT()
	case ocsd.OpFlush:
		resp = d.OnFlush()
	case ocsd.OpReset:
		resp = d.OnReset()
	default:
		d.Base.LogError(ocsd.ErrSevError, ocsd.ErrInvalidParamVal)
		resp = ocsd.RespFatalInvalidOp
	}
	return resp
}

func (d *PktDecode) accessMemory(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	return d.Base.AccessMemory(address, d.TraceID(), memSpace, reqBytes)
}

func (d *PktDecode) TraceID() uint8 {
	if d.config != nil {
		return d.config.TraceID()
	}
	return 0
}

func (d *PktDecode) configureDecoder() {
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
	d.outElem.SetSendIf(d.traceElemOutIf)
	if d.config != nil {
		d.outElem.SetCSID(d.config.TraceID())
	}
	d.returnStack = *common.NewAddrReturnStack()
	d.unsyncEOTInfo = ocsd.UnsyncInitDecoder
	d.unsyncPktIdx = ocsd.BadTrcIndex
	d.eteFirstTSMarker = false
	d.nextRangeCheckClear()
}

// traceElemOutIf returns the downstream GenElemProcessor (used as a func reference for outElem).
func (d *PktDecode) traceElemOutIf() ocsd.GenElemProcessor { return d.Base.TraceElemOut }

func (d *PktDecode) SetProtocolConfig(config *Config) error {
	d.Config = config
	d.config = config
	if d.config == nil {
		return ocsd.ErrInvalidParamVal
	}
	d.Base.ConfigInitOK = true
	// Extract basic config elements
	d.maxSpecDepth = int(d.config.MaxSpecDepth())
	d.configureDecoder()
	d.outElem.SetCSID(d.config.TraceID())
	d.outElem.SetSendIf(d.traceElemOutIf)

	// Match C++ decoder behavior: enable the return stack only when configured.
	if d.config.EnabledRetStack() {
		d.returnStack.SetActive(true)
	}

	// Match C++ static instruction decode configuration.
	d.instrInfo.DsbDmbWaypoints = 0
	if d.config.WfiwfeBranch() {
		d.instrInfo.WfiWfeBranch = 1
	} else {
		d.instrInfo.WfiWfeBranch = 0
	}
	d.instrInfo.PeType.Arch = d.config.ArchVer
	d.instrInfo.PeType.Profile = d.config.CoreProf
	d.instrInfo.TrackItBlock = 1
	d.instrInfo.ThumbItConditions = 0

	if v, ok := os.LookupEnv("OPENCSD_INSTR_RANGE_LIMIT"); ok {
		v = strings.TrimSpace(v)
		if v != "" {
			if parsed, err := strconv.ParseUint(v, 0, 32); err == nil {
				d.instrRangeLimit = uint32(parsed)
			}
		}
	}

	if v, ok := os.LookupEnv("OPENCSD_ERR_ON_AA64_BAD_OPCODE"); ok {
		v = strings.ToLower(strings.TrimSpace(v))
		d.aa64BadOpcode = v == "1" || v == "true" || v == "yes" || v == "on"
	}

	d.syncAA64OpcodeCheckMode()
	return nil
}

func (d *PktDecode) SetInstrRangeLimit(limit uint32) {
	d.instrRangeLimit = limit
}

func (d *PktDecode) syncAA64OpcodeCheckMode() {
	enabled := d.aa64BadOpcode || (d.Base.ComponentOpMode()&ocsd.OpflgPktdecAA64OpcodeChk) != 0
	if d.Base.InstrDecode == nil {
		return
	}
	if setter, ok := d.Base.InstrDecode.(interface{ SetAA64ErrOnBadOpcode(bool) }); ok {
		setter.SetAA64ErrOnBadOpcode(enabled)
	}
}

func (d *PktDecode) commitElemOnEOT() error {
	err := error(nil)

	if d.outElem.NumElemToSend() == 0 {
		d.outElem.ResetElemStack()
	}

	// Iterate from oldest (index 0) to newest, matching C++ back()/delete_back()
	// where back() returns the oldest element in the deque.
	for len(d.p0Stack) > 0 && err == nil {
		pElem := d.p0Stack[0] // oldest element (C++ back())
		switch pElem.p0Type {
		case p0TrcOn, p0Atom, p0Excep, p0ExcepRet, p0Q, p0UnseenUncommitted:
			// clear stack and stop
			d.poppedElems = append(d.poppedElems, d.p0Stack...)
			d.p0Stack = nil

		case p0Addr, p0Ctxt:
			// skip

		case p0TransStart:
			if d.config.CommTransP0() {
				d.poppedElems = append(d.poppedElems, d.p0Stack...)
				d.p0Stack = nil
			}

		case p0TransFail, p0TransCommit:
			if d.maxSpecDepth == 0 || d.currSpecDepth == 0 {
				err = d.processTransElem(pElem)
			}

		case p0TransTraceInit, p0TInfo:
			// skip

		case p0Event, p0TS, p0CC, p0TSCC:
			err = d.processTSCCEventElem(pElem)

		case p0Marker:
			err = d.processMarkerElem(pElem)

		case p0ITE:
			err = d.processITEElem(pElem)
		}
		if len(d.p0Stack) > 0 {
			d.poppedElems = append(d.poppedElems, d.p0Stack[0])
			d.p0Stack = d.p0Stack[1:] // pop oldest (C++ delete_back())
		}
	}

	if err == nil {
		err = d.outElem.AddElemType(d.Base.IndexCurrPkt, ocsd.GenElemEOTrace)
		reason := ocsd.UnsyncEOT
		if d.prevOverflow {
			reason = ocsd.UnsyncOverflow
		}
		d.outElem.CurrElem().SetUnSyncEOTReason(reason)
	}
	return err
}

func (d *PktDecode) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	var err error

	err = d.commitElemOnEOT()
	if err != nil {
		resp = ocsd.RespFatalInvalidData
		d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: Error flushing element stack at end of trace data.", err))
	} else {
		resp = d.outElem.SendElements()
	}
	return resp
}

func (d *PktDecode) OnReset() ocsd.DatapathResp {
	d.configureDecoder()
	d.unsyncEOTInfo = ocsd.UnsyncResetDecoder
	return ocsd.RespCont
}

func (d *PktDecode) OnFlush() ocsd.DatapathResp {
	if d.currState == resolveElem {
		return d.resolveElements()
	}
	return d.outElem.SendElements()
}

func (d *PktDecode) ProcessPacket() ocsd.DatapathResp {
	resp := ocsd.RespCont
	var err error
	d.syncAA64OpcodeCheckMode()

	pkt := d.CurrPacketIn
	pktDone := false

	for !pktDone {
		switch d.currState {
		case noSync:
			err = d.outElem.ResetElemStack()
			if err == nil {
				err = d.outElem.AddElemType(d.Base.IndexCurrPkt, ocsd.GenElemNoSync)
				if err == nil {
					d.outElem.CurrElem().SetUnSyncEOTReason(d.unsyncEOTInfo)
					resp = d.outElem.SendElements()
					d.currState = waitSync
				}
			}
			if err != nil {
				resp = ocsd.RespFatalSysErr
			}

		case waitSync:
			if pkt.Type == PktAsync {
				d.currState = waitISync
			}
			pktDone = true

		case waitISync:
			d.needCtxt = true
			d.needAddr = true
			if pkt.Type == PktTraceInfo {
				d.doTraceInfoPacket()
				d.currState = decodePkts
				d.returnStack.Flush()
			} else if d.config.MajVersion() >= 0x5 && pkt.Type == PktEvent {
				err = d.decodePacket()
				if err != nil {
					resp = ocsd.RespFatalInvalidData
				}
			}
			pktDone = true

		case decodePkts:
			err = d.decodePacket()
			if err != nil {
				// We don't have operational flags like componentOpMode in Go yet, so just fail on bad data
				resp = ocsd.RespFatalInvalidData
				pktDone = true
			} else if d.currState != resolveElem {
				pktDone = true
			}

		case resolveElem:
			resp = d.resolveElements()
			if d.currState == decodePkts || resp != ocsd.RespCont {
				pktDone = true
			}
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
			err := error(nil)
			if d.elemRes.P0Commit != 0 {
				err = d.commitElements()
			}

			if d.elemRes.P0Commit == 0 {
				if err == nil && d.elemRes.P0Cancel != 0 {
					err = d.cancelElements()
				}
				if err == nil && d.elemRes.Mispredict {
					err = d.mispredictAtom()
				}
				if err == nil && d.elemRes.Discard {
					err = d.discardElements()
				}
			}

			if err != nil {
				if d.currState == noSync {
					emitResp := d.emitNoSyncAtUnsyncIdx()
					if emitResp == ocsd.RespFatalSysErr {
						resp = emitResp
					} else {
						if d.currState == noSync {
							d.currState = waitSync
						}
						resp = ocsd.RespErrCont
					}
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

func (d *PktDecode) decodePacket() error {
	err := error(nil)
	pkt := d.CurrPacketIn
	isAddr := false

	switch pkt.Type {
	case PktAsync, PktIgnore:
		// Do nothing
	case PktTraceInfo:
		d.pushP0ElemParam(p0TInfo, false, pkt.Type, d.Base.IndexCurrPkt, nil)
	case PktTraceOn:
		d.pushP0ElemParam(p0TrcOn, false, pkt.Type, d.Base.IndexCurrPkt, nil)
	case PktAtomF1, PktAtomF2, PktAtomF3, PktAtomF4, PktAtomF5, PktAtomF6:
		d.pushP0ElemAtom(pkt.Type, d.Base.IndexCurrPkt, pkt.Atom)
		d.currSpecDepth += int(pkt.Atom.Num)
	case PktCtxt:
		d.pushP0ElemContext(pkt.Type, d.Base.IndexCurrPkt, pkt.Context, d.lastIS)
	case PktAddrMatch:
		addr := pkt.VAddr
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemAddr(pkt.Type, d.Base.IndexCurrPkt, addr, d.lastIS, false)
		isAddr = true
	case PktAddrCtxtL_64IS0, PktAddrCtxtL_64IS1, PktAddrCtxtL_32IS0, PktAddrCtxtL_32IS1:
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemContext(pkt.Type, d.Base.IndexCurrPkt, pkt.Context, d.lastIS)
		fallthrough
	case PktAddrL_32IS0, PktAddrL_32IS1, PktAddrL_64IS0, PktAddrL_64IS1, PktAddrS_IS0, PktAddrS_IS1:
		addr := pkt.VAddr
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemAddr(pkt.Type, d.Base.IndexCurrPkt, addr, d.lastIS, false)
		isAddr = true
	case ETE_PktSrcAddrMatch, ETE_PktSrcAddrS_IS0, ETE_PktSrcAddrS_IS1, ETE_PktSrcAddrL_32IS0, ETE_PktSrcAddrL_32IS1, ETE_PktSrcAddrL_64IS0, ETE_PktSrcAddrL_64IS1:
		addr := pkt.VAddr
		d.lastIS = pkt.VAddrISA
		d.pushP0ElemAddr(pkt.Type, d.Base.IndexCurrPkt, addr, d.lastIS, true)
		d.currSpecDepth++
	case PktExcept:
		d.pushP0ElemExcept(pkt.Type, d.Base.IndexCurrPkt, pkt.ExceptionInfo.AddrInterp == 0x2, pkt.ExceptionInfo.ExceptionType)
		d.elemPendingAddr = true
	case PktExceptRtn:
		bV7MProfile := (d.config.ArchVer == ocsd.ArchV7) && (d.config.CoreProf == ocsd.ProfileCortexM)
		d.pushP0ElemParam(p0ExcepRet, bV7MProfile, pkt.Type, d.Base.IndexCurrPkt, nil)
		if bV7MProfile {
			d.currSpecDepth++
		}

	case PktQ:
		e := d.allocP0Elem()
		e.p0Type = p0Q
		e.isP0 = true
		e.rootPkt = pkt.Type
		e.rootIndex = d.Base.IndexCurrPkt
		e.qCount = int(pkt.QPkt.QCount)
		if pkt.QPkt.AddrPresent {
			e.qHasAddr = true
			e.addrVal = pkt.VAddr
			e.addrIS = pkt.VAddrISA
			d.currSpecDepth++
		} else {
			d.elemPendingAddr = true
		}
		d.p0Stack = append(d.p0Stack, e)

	case PktFuncRet:
		// P0 element iff V8-M profile, otherwise ignored.
		if ocsd.IsV8Arch(d.config.ArchVer) && d.config.CoreProf == ocsd.ProfileCortexM {
			d.pushP0ElemParam(p0FuncRet, true, pkt.Type, d.Base.IndexCurrPkt, nil)
			d.currSpecDepth++
		}

	case PktBadSequence:
		d.handleBadPacket(d.Base.IndexCurrPkt, "Bad byte sequence in packet.")

	case PktBadTraceMode:
		d.handleBadPacket(d.Base.IndexCurrPkt, "Invalid packet type for trace mode.")

	case PktReserved:
		d.handleBadPacket(d.Base.IndexCurrPkt, "Reserved packet header")

	case PktReservedCfg:
		d.handleBadPacket(d.Base.IndexCurrPkt, "Reserved packet header for current configuration")

	// ETE timestamp marker compatibility alias
	case PktTypeTS_MARKER:
		marker := ocsd.TraceMarkerPayload{
			Type:  ocsd.ElemMarkerTS,
			Value: 0,
		}
		d.pushP0ElemMarker(pkt.Type, d.Base.IndexCurrPkt, marker)

	// ETE transactional memory packet compatibility aliases
	case PktTypeTRANS_ST:
		d.pushP0ElemParam(p0TransStart, d.config.CommTransP0(), pkt.Type, d.Base.IndexCurrPkt, nil)
		if d.config.CommTransP0() {
			d.currSpecDepth++
		}

	case PktTypeTRANS_COMMIT:
		d.pushP0ElemParam(p0TransCommit, false, pkt.Type, d.Base.IndexCurrPkt, nil)

	case PktTypeTRANS_FAIL:
		d.pushP0ElemParam(p0TransFail, false, pkt.Type, d.Base.IndexCurrPkt, nil)

	// ETE PE reset (exception without address) compatibility alias
	case PktTypePE_RESET:
		d.pushP0ElemExcept(pkt.Type, d.Base.IndexCurrPkt, false, pkt.ExceptionInfo.ExceptionType)

	// ETE instrumentation packet compatibility alias
	case PktTypeITE:
		ite := ocsd.TraceSWIte{
			EL:    pkt.ITEPkt.EL,
			Value: pkt.ITEPkt.Value,
		}
		d.pushP0ElemITE(pkt.Type, d.Base.IndexCurrPkt, ite)

	// ETE timestamp marker
	case ETE_PktTSMarker:
		marker := ocsd.TraceMarkerPayload{
			Type:  ocsd.ElemMarkerTS,
			Value: 0,
		}
		d.pushP0ElemMarker(pkt.Type, d.Base.IndexCurrPkt, marker)

	// ETE transactional memory packets
	case ETE_PktTransSt:
		d.pushP0ElemParam(p0TransStart, d.config.CommTransP0(), pkt.Type, d.Base.IndexCurrPkt, nil)
		if d.config.CommTransP0() {
			d.currSpecDepth++
		}

	case ETE_PktTransCommit:
		d.pushP0ElemParam(p0TransCommit, false, pkt.Type, d.Base.IndexCurrPkt, nil)

	case ETE_PktTransFail:
		d.pushP0ElemParam(p0TransFail, false, pkt.Type, d.Base.IndexCurrPkt, nil)

	// ETE PE reset (exception without address)
	case ETE_PktPeReset:
		d.pushP0ElemExcept(pkt.Type, d.Base.IndexCurrPkt, false, pkt.ExceptionInfo.ExceptionType)

	// ETE instrumentation packet
	case ETE_PktITE:
		ite := ocsd.TraceSWIte{
			EL:    pkt.ITEPkt.EL,
			Value: pkt.ITEPkt.Value,
		}
		d.pushP0ElemITE(pkt.Type, d.Base.IndexCurrPkt, ite)

	// event trace
	case PktEvent:
		params := []uint32{uint32(pkt.EventVal)}
		d.pushP0ElemParam(p0Event, false, pkt.Type, d.Base.IndexCurrPkt, params)

	// cycle count packets
	case PktCcntF1, PktCcntF2, PktCcntF3:
		params := []uint32{pkt.CycleCount}
		d.pushP0ElemParam(p0CC, false, pkt.Type, d.Base.IndexCurrPkt, params)
		d.elemRes.P0Commit = int(pkt.CommitElements)

	// timestamp
	case PktTimestamp:
		bTSwithCC := d.config.EnabledCCI()
		ts := pkt.Timestamp
		params := []uint32{
			uint32(ts & 0xFFFFFFFF),
			uint32((ts >> 32) & 0xFFFFFFFF),
		}
		if bTSwithCC {
			params = append(params, pkt.CycleCount)
		}
		p0Type := p0TS
		if bTSwithCC {
			p0Type = p0TSCC
		}
		d.pushP0ElemParam(p0Type, false, pkt.Type, d.Base.IndexCurrPkt, params)

	// speculation - mispredict/cancel with atoms
	case PktMispredict, PktCancelF1Mispred, PktCancelF2, PktCancelF3:
		d.elemRes.Mispredict = true
		if pkt.Atom.Num > 0 {
			d.pushP0ElemAtom(pkt.Type, d.Base.IndexCurrPkt, pkt.Atom)
			d.currSpecDepth += int(pkt.Atom.Num)
		}
		d.elemRes.P0Cancel = int(pkt.CancelElements)

	// cancel without mispredict
	case PktCancelF1:
		d.elemRes.P0Cancel = int(pkt.CancelElements)

	// commit
	case PktCommit:
		d.elemRes.P0Commit = int(pkt.CommitElements)

	// overflow (falls through to discard logic)
	case PktOverflow:
		d.prevOverflow = true
		d.currSpecDepth = 0
		d.elemRes.Discard = true

	// discard
	case PktDiscard:
		d.currSpecDepth = 0
		d.elemRes.Discard = true
	}

	if isAddr && d.elemPendingAddr {
		d.currSpecDepth++
		d.elemPendingAddr = false
	}

	if d.currSpecDepth > d.maxSpecDepth {
		d.elemRes.P0Commit = d.currSpecDepth - d.maxSpecDepth
	}

	if d.isElemForRes() {
		d.currState = resolveElem
	}

	return err
}

func (d *PktDecode) commitElements() error {
	err := error(nil)
	bPopElem := true
	numCommitReq := d.elemRes.P0Commit
	var errIdx ocsd.TrcIndex
	contextFlush := false

	err = d.outElem.ResetElemStack()

	for d.elemRes.P0Commit > 0 && err == nil && !contextFlush {
		if len(d.p0Stack) > 0 {
			pElem := d.p0Stack[0] // get oldest element
			errIdx = pElem.rootIndex
			bPopElem = true

			switch pElem.p0Type {
			case p0TrcOn:
				d.nextRangeCheckClear()
				err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemTraceOn)
				if err == nil {
					reason := ocsd.TraceOnNormal
					if d.prevOverflow {
						reason = ocsd.TraceOnOverflow
					}
					d.outElem.CurrElem().Payload.TraceOnReason = reason
					d.prevOverflow = false
					d.returnStack.Flush()
				}

			case p0Addr:
				d.returnStack.SetPopPending(false)
				if d.returnStack.IsTInfoWaitAddr() {
					// equivalent to is_t_info_wait_addr / clear_t_info_wait_addr
					d.returnStack.SetTInfoWaitAddr(false)
				}
				d.setInstrInfoInAddrISA(pElem.addrVal, pElem.addrIS)
				d.needAddr = false

			case p0Ctxt:
				if pElem.context.Updated {
					err = d.outElem.AddElem(pElem.rootIndex)
					if err == nil {
						d.updateContext(pElem, d.outElem.CurrElem())
						contextFlush = true
						d.Base.InvalidateMemAccCache(d.TraceID())
					}
				}

			case p0Event, p0TS, p0CC, p0TSCC:
				err = d.processTSCCEventElem(pElem)

			case p0Marker:
				err = d.processMarkerElem(pElem)

			case p0Atom:
				for !pElem.isEmpty() && d.elemRes.P0Commit > 0 && err == nil {
					atom := pElem.commitOldest()

					if err = d.returnStackPop(); err != nil {
						break
					}

					if !d.needCtxt && !d.needAddr {
						if err = d.processAtom(atom, pElem); err != nil {
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
				if err = d.returnStackPop(); err != nil {
					break
				}
				d.nextRangeCheckClear()
				err = d.processException(pElem)
				d.elemRes.P0Commit--

			case p0ExcepRet:
				d.nextRangeCheckClear()
				err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemExceptionRet)
				if err == nil {
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
				d.returnStack.SetTInfoWaitAddr(true) // tinfo_wait_addr
				d.returnStack.Flush()
			}
			if bPopElem {
				e := d.p0Stack[0]
				d.poppedElems = append(d.poppedElems, e)
				d.p0Stack = d.p0Stack[1:] // pop_front
			}
		} else {
			err = d.handlePacketSeqErr(ocsd.ErrCommitPktOverrun, errIdx, "Not enough elements to commit")
			d.elemRes.P0Commit = 0
			break
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
	d.nextRangeCheck.valid = false
}

func (d *PktDecode) nextRangeCheckSet(addr ocsd.VAddr) {
	d.nextRangeCheck.valid = true
	d.nextRangeCheck.nextStAddr = addr
}

func (d *PktDecode) nextRangeCheckOK(addr ocsd.VAddr) bool {
	if d.nextRangeCheck.valid {
		return d.nextRangeCheck.nextStAddr == addr
	}
	// no prior range state to validate against
	return true
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

func (d *PktDecode) returnStackPop() error {
	err := error(nil)
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

func (d *PktDecode) processTSCCEventElem(pElem *p0Elem) error {
	bPermitTS := !d.config.EteHasTSMarker() || d.eteFirstTSMarker
	var err error = nil

	switch pElem.p0Type {
	case p0Event:
		err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemEvent)
		if err == nil {
			d.outElem.CurrElem().Payload.TraceEvent.EvType = ocsd.EventNumbered
			d.outElem.CurrElem().Payload.TraceEvent.EvNumber = uint16(pElem.params[0])
		}
	case p0TS:
		if bPermitTS {
			err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemTimestamp)
			if err == nil {
				d.outElem.CurrElem().Timestamp = uint64(pElem.params[0]) | (uint64(pElem.params[1]) << 32)
			}
		}
	case p0CC:
		err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemCycleCount)
		if err == nil {
			d.outElem.CurrElem().SetCycleCount(pElem.params[0])
		}
	case p0TSCC:
		if bPermitTS {
			err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemTimestamp)
			if err == nil {
				d.outElem.CurrElem().Timestamp = uint64(pElem.params[0]) | (uint64(pElem.params[1]) << 32)
				d.outElem.CurrElem().SetCycleCount(pElem.params[2])
			}
		}
	}
	return err
}

func (d *PktDecode) processMarkerElem(pElem *p0Elem) error {
	if d.config.EteHasTSMarker() && pElem.marker.Type == ocsd.ElemMarkerTS {
		d.eteFirstTSMarker = true
	}

	err := d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemSyncMarker)
	if err == nil {
		d.outElem.CurrElem().Payload.SyncMarker = pElem.marker
	}
	return err
}

func (d *PktDecode) processTransElem(pElem *p0Elem) error {
	err := d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemMemTrans)
	if err == nil {
		tt := ocsd.MemTransFail - ocsd.TraceMemtrans(p0TransFail-pElem.p0Type)
		d.outElem.CurrElem().Payload.MemTrans = tt
	}
	return err
}

func (d *PktDecode) processITEElem(pElem *p0Elem) error {
	err := d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemInstrumentation)
	if err == nil {
		d.outElem.CurrElem().Payload.SWIte = pElem.ite
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

func (d *PktDecode) traceInstrToWP(rangeOut *instrRange, res *wpRes, traceToAddrNext bool, nextAddrMatch ocsd.VAddr) error {
	var err error
	rangeOut.stAddr = d.instrInfo.InstrAddr
	rangeOut.enAddr = d.instrInfo.InstrAddr
	rangeOut.numInstr = 0
	*res = wpNotFound

	for *res == wpNotFound {
		bytesReq := uint32(4)
		currMemSpace := d.getCurrMemSpace()
		bytesRead, memData, errMem := d.accessMemory(d.instrInfo.InstrAddr, currMemSpace, bytesReq)
		if errMem != nil {
			return errMem
		}

		if bytesRead == 4 {
			opcode := uint32(memData[0]) | uint32(memData[1])<<8 | uint32(memData[2])<<16 | uint32(memData[3])<<24
			d.instrInfo.Opcode = opcode
			err = d.Base.InstrDecodeCall(&d.instrInfo)
			if err != nil {
				break
			}

			d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
			rangeOut.numInstr++
			if d.instrRangeLimit > 0 && rangeOut.numInstr > d.instrRangeLimit {
				return ocsd.ErrIRangeLimitOverrun
			}

			if traceToAddrNext {
				if d.instrInfo.InstrAddr == nextAddrMatch {
					*res = wpFound
				}
			} else if d.instrInfo.Type != ocsd.InstrOther {
				*res = wpFound
			}
		} else if bytesRead == 2 && d.instrInfo.Isa == ocsd.ISAThumb2 {
			// Fallback for 16-bit Thumb instructions at a memory region boundary.
			val := uint16(memData[0]) | uint16(memData[1])<<8
			if (val & 0xF800) < 0xE800 { // valid 16-bit Thumb encoding
				d.instrInfo.Opcode = uint32(val)
				err = d.Base.InstrDecodeCall(&d.instrInfo)
				if err != nil {
					break
				}

				d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
				rangeOut.numInstr++
				if d.instrRangeLimit > 0 && rangeOut.numInstr > d.instrRangeLimit {
					return ocsd.ErrIRangeLimitOverrun
				}

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
		} else {
			*res = wpNacc
		}
	}
	rangeOut.enAddr = d.instrInfo.InstrAddr
	return err
}

func (d *PktDecode) processAtom(atom ocsd.AtmVal, pElem *p0Elem) error {
	var WPRes wpRes
	var addrRange instrRange
	ETE_ERET := false

	err := d.outElem.AddElem(pElem.rootIndex)
	if err != nil {
		return err
	}

	err = d.traceInstrToWP(&addrRange, &WPRes, false, 0)
	if err != nil {
		if err == ocsd.ErrUnsupportedISA {
			d.needAddr = true
			d.needCtxt = true
			{
				d.Base.LogError(ocsd.ErrSevWarn, fmt.Errorf("%w: Warning: unsupported instruction set processing atom packet.", err))
			}
			return nil
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
				d.returnStack.SetPopPending(true)
				if d.config.MajVersion() >= 0x5 && d.instrInfo.SubType == ocsd.SInstrV8Eret {
					ETE_ERET = true // simulate ETE ERET
				}
			}
		}

		d.setElemTraceRange(d.outElem.CurrElem(), addrRange, atom == ocsd.AtomE, pElem.rootIndex)

		// Check for discontinuous ranges that can indicate an inconsistent/corrupt
		// program image used for decode. Mirrors the C++ etmv4 decoder logic.
		if !d.nextRangeCheckOK(addrRange.stAddr) {
			return d.handleBadImageError(pElem.rootIndex, "Discontinuous ranges - Inconsistent program image for decode\n")
		}
		if atom == ocsd.AtomN {
			// Branch not taken, next range is expected to continue at nextAddr.
			d.nextRangeCheckSet(nextAddr)
		} else {
			// Taken branch breaks linear continuity expectation.
			d.nextRangeCheckClear()
		}

		if ETE_ERET {
			err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemExceptionRet)
			if err != nil {
				return err
			}
		}
	} else {
		d.needAddr = true
		d.nextRangeCheckClear()

		if addrRange.stAddr != addrRange.enAddr {
			d.setElemTraceRange(d.outElem.CurrElem(), addrRange, true, pElem.rootIndex)
			if WPRes == wpNacc {
				err = d.outElem.AddElem(pElem.rootIndex)
			}
		}

		if WPRes == wpNacc && err == nil {
			d.outElem.CurrElem().SetType(ocsd.GenElemAddrNacc)
			d.outElem.CurrElem().StAddr = d.instrInfo.InstrAddr

			currMemSpace := d.getCurrMemSpace()
			d.outElem.CurrElem().Payload.ExceptionNum = uint32(currMemSpace)
		}
	}
	return nil
}

func (d *PktDecode) processException(pElem *p0Elem) error {
	var err error
	var pCtxtElem *p0Elem
	var pAddressElem *p0Elem

	pExceptElem := pElem
	excepPktIndex := pExceptElem.rootIndex
	branchTarget := pExceptElem.prevSame
	ETE_resetPkt := pExceptElem.rootPkt == ETE_PktPeReset

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
			return d.handlePacketSeqErr(ocsd.ErrBadPacketSeq, d.Base.IndexCurrPkt, "Address missing in exception packet.")
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
	if err != nil {
		return err
	}

	if pCtxtElem != nil {
		d.updateContext(pCtxtElem, d.outElem.CurrElem())
		err = d.outElem.AddElem(excepPktIndex)
		if err != nil {
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
			if err != nil {
				if err == ocsd.ErrUnsupportedISA {
					d.needAddr = true
					d.needCtxt = true
					d.Base.LogError(ocsd.ErrSevWarn, fmt.Errorf("%w: Warning: unsupported instruction set processing exception packet.", err))
				} else {
					d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: Error processing exception packet.", err))
				}
				return err
			}

			if WPRes == wpFound {
				d.setElemTraceRange(d.outElem.CurrElem(), addrRange, true, excepPktIndex)
				rangeOut = true
			} else {
				d.needAddr = true
				if addrRange.stAddr != addrRange.enAddr {
					d.setElemTraceRange(d.outElem.CurrElem(), addrRange, true, excepPktIndex)
					rangeOut = true
				}
			}

			if rangeOut {
				err = d.outElem.AddElem(excepPktIndex)
				if err != nil {
					return err
				}
			}
		}

		if WPRes == wpNacc {
			d.outElem.CurrElem().SetType(ocsd.GenElemAddrNacc)
			d.outElem.CurrElem().StAddr = d.instrInfo.InstrAddr
			d.outElem.CurrElem().Payload.ExceptionNum = uint32(d.getCurrMemSpace())

			err = d.outElem.AddElem(excepPktIndex)
			if err != nil {
				return err
			}
		}
	}

	d.outElem.CurrElem().SetType(ocsd.GenElemException)
	d.outElem.CurrElem().EnAddr = excepRetAddr
	d.outElem.CurrElem().SetExcepRetAddr(true)
	if bMTailChain {
		d.outElem.CurrElem().SetExcepRetAddr(false)
		d.outElem.CurrElem().SetExcepMTailChain(true)
	}
	d.outElem.CurrElem().SetExcepRetAddrBrTgt(branchTarget)
	d.outElem.CurrElem().Payload.ExceptionNum = uint32(pExceptElem.excepNum)

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

func (d *PktDecode) processSourceAddress(pElem *p0Elem) error {
	var err error
	srcAddr := pElem.addrVal
	currAddr := d.instrInfo.InstrAddr
	var outRange instrRange
	bSplitRangeOnN := (d.ComponentOpMode() & ocsd.OpflgPktdecSrcAddrNAtoms) != 0

	bytesReq := uint32(4)
	bytesRead, memData, errMem := d.accessMemory(srcAddr, d.getCurrMemSpace(), bytesReq)
	if errMem != nil {
		d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: Mem access error processing source address packet.", errMem))
		return errMem
	}

	if bytesRead != 4 {
		err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemAddrNacc)
		d.outElem.CurrElem().StAddr = srcAddr
		d.outElem.CurrElem().Payload.ExceptionNum = uint32(d.getCurrMemSpace())
		return err
	}

	opcode := uint32(memData[0]) | uint32(memData[1])<<8 | uint32(memData[2])<<16 | uint32(memData[3])<<24
	d.instrInfo.Opcode = opcode
	d.instrInfo.InstrAddr = srcAddr
	err = d.Base.InstrDecodeCall(&d.instrInfo)
	if err != nil {
		d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: Instruction decode error processing source address packet.", err))
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
				bytesRead, mData, eMem := d.accessMemory(instr.InstrAddr, d.getCurrMemSpace(), bytesReq)
				if eMem != nil {
					return eMem
				}

				if bytesRead == 4 {
					instr.Opcode = uint32(mData[0]) | uint32(mData[1])<<8 | uint32(mData[2])<<16 | uint32(mData[3])<<24
					eDec := d.Base.InstrDecodeCall(&instr)
					if eDec != nil {
						return eDec
					}
					instr.InstrAddr += ocsd.VAddr(instr.InstrSize)
					outRange.numInstr++
					if bSplitRangeOnN && instr.InstrAddr < outRange.enAddr && instr.Type != ocsd.InstrOther {
						midRange := outRange
						midRange.enAddr = instr.InstrAddr
						err = d.outElem.AddElem(pElem.rootIndex)
						if err != nil {
							return err
						}
						d.setElemTraceRangeInstr(d.outElem.CurrElem(), midRange, false, pElem.rootIndex, &instr)
						outRange.stAddr = midRange.enAddr
						outRange.numInstr = 0
					}
				} else {
					bMemAccErr = true
					err = d.outElem.AddElemType(pElem.rootIndex, ocsd.GenElemAddrNacc)
					if err != nil {
						return err
					}
					d.outElem.CurrElem().StAddr = srcAddr
					d.outElem.CurrElem().Payload.ExceptionNum = uint32(d.getCurrMemSpace())
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
		d.returnStack.SetPopPending(true)
	}
	d.instrInfo.Isa = d.instrInfo.NextIsa

	d.outElem.AddElem(pElem.rootIndex)
	d.setElemTraceRange(d.outElem.CurrElem(), outRange, true, pElem.rootIndex)

	return err
}

func (d *PktDecode) processQElement(pElem *p0Elem) error {
	var err error
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
			d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: Address missing in Q packet.", ocsd.ErrBadPacketSeq))
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
	if err != nil {
		return err
	}

	var addrRange instrRange
	addrRange.stAddr = d.instrInfo.InstrAddr
	addrRange.enAddr = d.instrInfo.InstrAddr
	addrRange.numInstr = 0
	isBranch := false

	for range iCount {
		bytesReq := uint32(4)
		bytesRead, memData, errMem := d.accessMemory(d.instrInfo.InstrAddr, d.getCurrMemSpace(), bytesReq)
		if errMem != nil {
			break
		}

		if bytesRead == 4 {
			opcode := uint32(memData[0]) | uint32(memData[1])<<8 | uint32(memData[2])<<16 | uint32(memData[3])<<24
			d.instrInfo.Opcode = opcode
			eDec := d.Base.InstrDecodeCall(&d.instrInfo)
			if eDec != nil {
				break
			}

			d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
			addrRange.numInstr++

			isBranch = (d.instrInfo.Type == ocsd.InstrBr) || (d.instrInfo.Type == ocsd.InstrBrIndirect)
			if isBranch {
				break
			}
		} else if bytesRead == 2 && d.instrInfo.Isa == ocsd.ISAThumb2 {
			// Fallback for 16-bit Thumb instructions at a memory region boundary.
			val := uint16(memData[0]) | uint16(memData[1])<<8
			if (val & 0xF800) < 0xE800 { // valid 16-bit Thumb encoding
				d.instrInfo.Opcode = uint32(val)
				eDec := d.Base.InstrDecodeCall(&d.instrInfo)
				if eDec != nil {
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
		} else {
			break
		}
	}

	inCompleteRange := true
	if iCount > 0 && addrRange.numInstr == uint32(iCount) {
		if d.instrInfo.InstrAddr == qAddr || isBranch {
			inCompleteRange = false
			addrRange.enAddr = d.instrInfo.InstrAddr
			d.setElemTraceRange(d.outElem.CurrElem(), addrRange, true, pElem.rootIndex)
		}
	}

	if inCompleteRange {
		addrRange.enAddr = qAddr
		addrRange.numInstr = uint32(iCount)

		d.outElem.CurrElem().SetType(ocsd.GenElemIRangeNopath)
		d.outElem.CurrElem().StAddr = addrRange.stAddr
		d.outElem.CurrElem().EnAddr = addrRange.enAddr
		d.outElem.CurrElem().Payload.NumInstrRange = addrRange.numInstr
		d.outElem.CurrElem().ISA = d.calcISA(d.is64bit, qIs)
	}

	d.setInstrInfoInAddrISA(qAddr, qIs)
	d.needAddr = false

	return err
}

func (d *PktDecode) cancelElements() error {
	err := error(nil)
	p0StackDone := false
	temp := make([]*p0Elem, 0)
	numCancelReq := d.elemRes.P0Cancel

	for d.elemRes.P0Cancel > 0 {
		if !p0StackDone {
			if len(d.p0Stack) == 0 {
				p0StackDone = true
			} else {
				// get the newest element (end of slice)
				lastIdx := len(d.p0Stack) - 1
				pElem := d.p0Stack[lastIdx]
				if pElem.isP0 {
					if pElem.p0Type == p0Atom {
						d.elemRes.P0Cancel -= pElem.cancelNewest(d.elemRes.P0Cancel)
						if pElem.isEmpty() {
							d.poppedElems = append(d.poppedElems, d.p0Stack[lastIdx])
							d.p0Stack = d.p0Stack[:lastIdx]
						}
					} else {
						d.elemRes.P0Cancel--
						d.poppedElems = append(d.poppedElems, d.p0Stack[lastIdx])
						d.p0Stack = d.p0Stack[:lastIdx]
					}
				} else {
					switch pElem.p0Type {
					case p0Event, p0TS, p0CC, p0TSCC, p0Marker, p0ITE:
						temp = append(temp, pElem)
						d.p0Stack = d.p0Stack[:lastIdx]
					default:
						d.poppedElems = append(d.poppedElems, d.p0Stack[lastIdx])
						d.p0Stack = d.p0Stack[:lastIdx]
					}
				}
				if len(d.p0Stack) == 0 {
					p0StackDone = true
				}
			}
		} else {
			err = ocsd.ErrCommitPktOverrun
			err = d.handlePacketSeqErr(err, d.Base.IndexCurrPkt, "Not enough elements to cancel")
			d.elemRes.P0Cancel = 0
			break
		}
	}

	// Restore saved elements back to the newest end in original order.
	for i := len(temp) - 1; i >= 0; i-- {
		d.p0Stack = append(d.p0Stack, temp[i])
	}

	d.currSpecDepth -= numCancelReq - d.elemRes.P0Cancel
	return err
}

func (d *PktDecode) mispredictAtom() error {
	err := error(nil)
	bFoundAtom := false
	bDone := false

	// Iterate from newest (end) to oldest, mirroring C++ front() iteration.
	for i := len(d.p0Stack) - 1; i >= 0 && !bDone; i-- {
		pElem := d.p0Stack[i]
		if pElem.p0Type == p0Atom {
			pElem.mispredictNewest()
			bFoundAtom = true
			bDone = true
		} else if pElem.p0Type == p0Addr {
			// discard address elements between mispredict and the atom
			d.poppedElems = append(d.poppedElems, pElem)
			d.p0Stack = append(d.p0Stack[:i], d.p0Stack[i+1:]...)
		} else if pElem.p0Type == p0UnseenUncommitted {
			// mispredict in one of the uncommitted elements before sync - disregard
			bDone = true
			bFoundAtom = true
		}
		// for any other type: continue scanning toward older elements
	}

	if !bFoundAtom {
		err = d.handlePacketSeqErr(ocsd.ErrCommitPktOverrun, d.Base.IndexCurrPkt, "Not found mispredict atom")
	}
	d.elemRes.Mispredict = false
	return err
}

func (d *PktDecode) discardElements() error {
	var err error

	for len(d.p0Stack) > 0 && err == nil {
		// Process oldest element first, mirroring C++ back() on a newest-first deque.
		pElem := d.p0Stack[0]

		if pElem.p0Type == p0Marker {
			err = d.processMarkerElem(pElem)
		} else if pElem.p0Type == p0ITE {
			err = d.processITEElem(pElem)
		} else {
			err = d.processTSCCEventElem(pElem)
		}
		d.poppedElems = append(d.poppedElems, pElem)
		d.p0Stack = d.p0Stack[1:]
	}

	d.clearElemRes()
	d.currSpecDepth = 0

	d.currState = noSync
	if d.prevOverflow {
		d.unsyncEOTInfo = ocsd.UnsyncOverflow
	} else {
		d.unsyncEOTInfo = ocsd.UnsyncDiscard
	}

	// unsync so need context & address
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
		d.pushP0ElemParam(p0UnseenUncommitted, true, pkt.Type, d.Base.IndexCurrPkt, nil)
	}

	d.pushP0ElemParam(p0TInfo, false, pkt.Type, d.Base.IndexCurrPkt, nil)

	if pkt.TraceInfo.InTransState {
		d.pushP0ElemParam(p0TransTraceInit, false, pkt.Type, d.Base.IndexCurrPkt, nil)
	}
}

func (d *PktDecode) handlePacketSeqErr(err error, idx ocsd.TrcIndex, reason string) error {
	d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: %s", err, reason))
	d.resetDecoderState()
	d.currState = noSync
	d.unsyncEOTInfo = ocsd.UnsyncBadPacket
	d.unsyncPktIdx = idx
	return err
}

func (d *PktDecode) handleBadPacket(idx ocsd.TrcIndex, reason string) {
	d.Base.LogError(ocsd.ErrSevWarn, fmt.Errorf("%w: %s", ocsd.ErrBadDecodePkt, reason))
	d.resetDecoderState()
	d.currState = noSync
	d.unsyncEOTInfo = ocsd.UnsyncBadPacket
	d.unsyncPktIdx = idx
}

func (d *PktDecode) handleBadImageError(idx ocsd.TrcIndex, reason string) error {
	d.Base.LogError(ocsd.ErrSevError, fmt.Errorf("%w: %s", ocsd.ErrBadDecodeImage, reason))
	d.resetDecoderState()
	d.currState = noSync
	d.unsyncEOTInfo = ocsd.UnsyncBadImage
	return ocsd.ErrBadDecodeImage
}

func (d *PktDecode) resetDecoderState() {
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
	d.unsyncEOTInfo = ocsd.UnsyncResetDecoder
	d.unsyncPktIdx = ocsd.BadTrcIndex
	d.eteFirstTSMarker = false
	d.nextRangeCheckClear()

	if d.outElem.ResetElemStack() != nil {
		d.outElem = *common.NewGenElemStack()
		if d.config != nil {
			d.outElem.SetCSID(d.config.TraceID())
		}
		d.outElem.SetSendIf(d.traceElemOutIf)
	}

	d.returnStack = *common.NewAddrReturnStack()
	if d.config != nil && d.config.EnabledRetStack() {
		d.returnStack.SetActive(true)
	}
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

func (d *PktDecode) emitNoSyncAtUnsyncIdx() ocsd.DatapathResp {
	idx := d.unsyncPktIdx
	if idx == ocsd.BadTrcIndex {
		return ocsd.RespCont
	}
	d.unsyncPktIdx = ocsd.BadTrcIndex
	if err := d.outElem.ResetElemStack(); err != nil {
		return ocsd.RespFatalSysErr
	}
	if err := d.outElem.AddElemType(idx, ocsd.GenElemNoSync); err != nil {
		return ocsd.RespFatalSysErr
	}
	d.outElem.CurrElem().SetUnSyncEOTReason(d.unsyncEOTInfo)
	return d.outElem.SendElements()
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

func (d *PktDecode) pushP0ElemMarker(rootPkt PktType, rootIndex ocsd.TrcIndex, marker ocsd.TraceMarkerPayload) {
	e := d.allocP0Elem()
	e.p0Type = p0Marker
	e.isP0 = false
	e.rootPkt = rootPkt
	e.rootIndex = rootIndex
	e.marker = marker
	d.p0Stack = append(d.p0Stack, e)
}

func (d *PktDecode) pushP0ElemITE(rootPkt PktType, rootIndex ocsd.TrcIndex, ite ocsd.TraceSWIte) {
	e := d.allocP0Elem()
	e.p0Type = p0ITE
	e.isP0 = false
	e.rootPkt = rootPkt
	e.rootIndex = rootIndex
	e.ite = ite
	d.p0Stack = append(d.p0Stack, e)
}

// DecoderManager is the registry factory for ETMv4 decoders
type DecoderManager struct{}

// NewConfiguredProcessor creates an ETMv4 packet processor with a typed config.
func NewConfiguredProcessor(cfg *Config) (*Processor, error) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	return NewProcessor(cfg), nil
}

// NewConfiguredPktDecode creates an ETMv4 packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	_ = instID
	decoder := NewPktDecode(cfg, nil)
	return decoder, nil
}

// NewConfiguredPipeline creates and wires a typed ETMv4 processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*Processor, *PktDecode, error) {
	proc, err := NewConfiguredProcessor(cfg)
	if err != nil {
		return nil, nil, err
	}
	decoder, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(decoder)
	return proc, decoder, nil
}

func typedConfig(config any) (*Config, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, ocsd.ErrInvalidParamVal
	}
	return cfg, nil
}

func (m *DecoderManager) CreatePacketProcessor(instID int, config any) (ocsd.TrcDataProcessor, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, createErr := NewConfiguredProcessor(cfg)
	if createErr != nil {
		return nil, nil, createErr
	}
	return proc, proc, nil
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (ocsd.TrcDataProcessor, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, decoder, createErr := NewConfiguredPipeline(instID, cfg)
	if createErr != nil {
		return nil, nil, createErr
	}
	return proc, decoder, nil
}

func (m *DecoderManager) Protocol() ocsd.TraceProtocol {
	return ocsd.ProtocolETMV4I
}
