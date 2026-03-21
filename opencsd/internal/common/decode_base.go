package common

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

// TargetMemAccess represents ITargetMemAccess.
// Interface to memory access.
type TargetMemAccess interface {
	ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err)
	InvalidateMemAccCache(csTraceID uint8)
}

// InstrDecode represents IInstrDecode.
// Interface to instruction decoding.
type InstrDecode interface {
	DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err
}

// TrcPktIndexer represents ITrcPktIndexer.
// Interface designed to allow tracing of packets back to the source data stream.
type TrcPktIndexer[Pt any] interface {
	TracePktIndex(indexSOP ocsd.TrcIndex, pktType Pt)
}

// PktDataIn represents IPktDataIn<P>.
type PktDataIn[P any] interface {
	PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *P) ocsd.DatapathResp
}

// PktRawDataMon represents IPktRawDataMon<P>.
type PktRawDataMon[P any] interface {
	RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *P, rawData []byte)
}

// PktDecodeStrategy defines the core strategy for packet decode processing.
type PktDecodeStrategy[P any, Pc any] interface {
	ProcessPacket() ocsd.DatapathResp
}

// Optional decode hooks.
type PktDecodeEOTHook interface{ OnEOT() ocsd.DatapathResp }
type PktDecodeResetHook interface{ OnReset() ocsd.DatapathResp }
type PktDecodeFlushHook interface{ OnFlush() ocsd.DatapathResp }
type PktDecodeProtocolConfigHook interface{ OnProtocolConfig() ocsd.Err }
type PktDecodeTraceIDProvider interface{ GetTraceID() uint8 }
type PktDecodeFirstInitHook interface{ OnFirstInitOK() }

// PktProcStrategy defines the core strategy for packet processing.
type PktProcStrategy[P any, Pt any, Pc any] interface {
	ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error)
}

// Optional processor hooks.
type PktProcEOTHook interface{ OnEOT() ocsd.DatapathResp }
type PktProcResetHook interface{ OnReset() ocsd.DatapathResp }
type PktProcFlushHook interface{ OnFlush() ocsd.DatapathResp }
type PktProcProtocolConfigHook interface{ OnProtocolConfig() ocsd.Err }
type PktProcBadPacketHook interface{ IsBadPacket() bool }

// PktDecodeI represents TrcPktDecodeI.
type PktDecodeI struct {
	TraceComponent

	TraceElemOut AttachPt[interfaces.TrcGenElemIn]
	MemAccess    AttachPt[TargetMemAccess]
	InstrDecode  AttachPt[InstrDecode]

	IndexCurrPkt ocsd.TrcIndex

	decodeInitOK  bool
	configInitOK  bool
	usesMemAccess bool
	usesIDecode   bool

	traceIDProvider PktDecodeTraceIDProvider
	onFirstInitOK   PktDecodeFirstInitHook
}

func (p *PktDecodeI) GetTraceElemOutAttachPt() *AttachPt[interfaces.TrcGenElemIn] {
	return &p.TraceElemOut
}
func (p *PktDecodeI) GetInstrDecodeAttachPt() *AttachPt[InstrDecode] { return &p.InstrDecode }
func (p *PktDecodeI) GetMemAccAttachPt() *AttachPt[TargetMemAccess]  { return &p.MemAccess }

func (p *PktDecodeI) InitPktDecodeI(name string) {
	p.InitTraceComponent(name)
	p.TraceElemOut = *NewAttachPt[interfaces.TrcGenElemIn]()
	p.MemAccess = *NewAttachPt[TargetMemAccess]()
	p.InstrDecode = *NewAttachPt[InstrDecode]()
	p.usesMemAccess = true
	p.usesIDecode = true
}

func (p *PktDecodeI) SetUsesMemAccess(uses bool) { p.usesMemAccess = uses }
func (p *PktDecodeI) GetUsesMemAccess() bool     { return p.usesMemAccess }

func (p *PktDecodeI) SetUsesIDecode(uses bool) { p.usesIDecode = uses }
func (p *PktDecodeI) GetUsesIDecode() bool     { return p.usesIDecode }

func (p *PktDecodeI) ensureDecodeReady() (bool, string) {
	if p.decodeInitOK {
		return true, ""
	}

	if !p.configInitOK {
		return false, "No decoder configuration information"
	}
	if !p.TraceElemOut.HasAttachedAndEnabled() {
		return false, "No element output interface attached and enabled"
	}
	if p.usesMemAccess && !p.MemAccess.HasAttachedAndEnabled() {
		return false, "No memory access interface attached and enabled"
	}
	if p.usesIDecode && !p.InstrDecode.HasAttachedAndEnabled() {
		return false, "No instruction decoder interface attached and enabled"
	}

	p.decodeInitOK = true
	if p.onFirstInitOK != nil {
		p.onFirstInitOK.OnFirstInitOK()
	}

	return true, ""
}

func (p *PktDecodeI) OutputTraceElement(elem *ocsd.TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.HasAttachedAndEnabled() && p.traceIDProvider != nil {
		return p.TraceElemOut.First().TraceElemIn(p.IndexCurrPkt, p.traceIDProvider.GetTraceID(), elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) OutputTraceElementIdx(idx ocsd.TrcIndex, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.HasAttachedAndEnabled() && p.traceIDProvider != nil {
		return p.TraceElemOut.First().TraceElemIn(idx, p.traceIDProvider.GetTraceID(), elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) InstrDecodeCall(instrInfo *ocsd.InstrInfo) ocsd.Err {
	if p.usesIDecode {
		if p.InstrDecode.HasAttachedAndEnabled() {
			return p.InstrDecode.First().DecodeInstruction(instrInfo)
		}
	}
	return ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) AccessMemory(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	if p.usesMemAccess {
		if p.MemAccess.HasAttachedAndEnabled() && p.traceIDProvider != nil {
			return p.MemAccess.First().ReadTargetMemory(address, p.traceIDProvider.GetTraceID(), memSpace, reqBytes)
		}
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) InvalidateMemAccCache() ocsd.Err {
	if !p.usesMemAccess {
		return ocsd.ErrDcdInterfaceUnused
	}
	if p.MemAccess.HasAttachedAndEnabled() && p.traceIDProvider != nil {
		p.MemAccess.First().InvalidateMemAccCache(p.traceIDProvider.GetTraceID())
	}
	return ocsd.OK
}

// PktDecodeBase represents TrcPktDecodeBase<P, Pc>.
type PktDecodeBase[P any, Pc any] struct {
	PktDecodeI
	Config       *Pc
	CurrPacketIn *P
	strategy     PktDecodeStrategy[P, Pc]
}

func (pb *PktDecodeBase[P, Pc]) InitPktDecodeBase(name string) {
	pb.InitPktDecodeI(name)
}

func (pb *PktDecodeBase[P, Pc]) SetStrategy(strategy PktDecodeStrategy[P, Pc]) {
	pb.strategy = strategy
	if traceIDProvider, ok := any(strategy).(PktDecodeTraceIDProvider); ok {
		pb.traceIDProvider = traceIDProvider
	} else {
		pb.traceIDProvider = nil
	}
	if firstInitHook, ok := any(strategy).(PktDecodeFirstInitHook); ok {
		pb.onFirstInitOK = firstInitHook
	} else {
		pb.onFirstInitOK = nil
	}
}

func (pb *PktDecodeBase[P, Pc]) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *P) ocsd.DatapathResp {
	resp := ocsd.RespCont
	if ready, reason := pb.ensureDecodeReady(); !ready {
		pb.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrNotInit, reason))
		return ocsd.RespFatalNotInit
	}

	switch op {
	case ocsd.OpData:
		if pktIn == nil {
			pb.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, ""))
			resp = ocsd.RespFatalInvalidParam
		} else {
			pb.CurrPacketIn = pktIn
			pb.IndexCurrPkt = indexSOP
			if pb.strategy != nil {
				resp = pb.strategy.ProcessPacket()
			}
		}
	case ocsd.OpEOT:
		if hook, ok := any(pb.strategy).(PktDecodeEOTHook); ok {
			resp = hook.OnEOT()
		}
	case ocsd.OpFlush:
		if hook, ok := any(pb.strategy).(PktDecodeFlushHook); ok {
			resp = hook.OnFlush()
		}
	case ocsd.OpReset:
		if hook, ok := any(pb.strategy).(PktDecodeResetHook); ok {
			resp = hook.OnReset()
		}
	default:
		pb.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, ""))
		resp = ocsd.RespFatalInvalidOp
	}
	return resp
}

func (pb *PktDecodeBase[P, Pc]) SetProtocolConfig(config *Pc) ocsd.Err {
	if config != nil {
		pb.Config = config
		if hook, ok := any(pb.strategy).(PktDecodeProtocolConfigHook); ok {
			err := hook.OnProtocolConfig()
			if err == ocsd.OK {
				pb.configInitOK = true
			}
			return err
		}
		pb.configInitOK = true
		return ocsd.OK
	}
	return ocsd.ErrInvalidParamVal
}

// PktProcI represents TrcPktProcI.
type PktProcI struct {
	TraceComponent
}

func (p *PktProcI) InitPktProcI(name string) {
	p.InitTraceComponent(name)
}

// PktProcBase represents TrcPktProcBase<P, Pt, Pc>.
type PktProcBase[P any, Pt any, Pc any] struct {
	PktProcI
	Config      *Pc
	PktOutI     AttachPt[PktDataIn[P]]
	PktRawMonI  AttachPt[PktRawDataMon[P]]
	PktIndexerI AttachPt[TrcPktIndexer[Pt]]
	Stats       ocsd.DecodeStats
	statsInit   bool
	strategy    PktProcStrategy[P, Pt, Pc]
}

func (pb *PktProcBase[P, Pt, Pc]) InitPktProcBase(name string) {
	pb.InitPktProcI(name)
	pb.PktOutI = *NewAttachPt[PktDataIn[P]]()
	pb.PktRawMonI = *NewAttachPt[PktRawDataMon[P]]()
	pb.PktIndexerI = *NewAttachPt[TrcPktIndexer[Pt]]()
	pb.ResetStats()
}

func (pb *PktProcBase[P, Pt, Pc]) SetStrategy(strategy PktProcStrategy[P, Pt, Pc]) {
	pb.strategy = strategy
}

func (pb *PktProcBase[P, Pt, Pc]) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp, error) {
	resp := ocsd.RespCont
	var processed uint32 = 0
	var err error

	switch op {
	case ocsd.OpData:
		if len(dataBlock) == 0 {
			pb.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "Packet Processor: Zero length data block error"))
			resp = ocsd.RespFatalInvalidParam
		} else {
			if pb.strategy != nil {
				processed, resp, err = pb.strategy.ProcessData(index, dataBlock)
			}
		}
	case ocsd.OpEOT:
		resp = pb.EOT()
	case ocsd.OpFlush:
		resp = pb.Flush()
	case ocsd.OpReset:
		resp = pb.ResetFn(index)
	default:
		pb.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "Packet Processor : Unknown Datapath operation"))
		resp = ocsd.RespFatalInvalidOp
	}
	return processed, resp, err
}

func (pb *PktProcBase[P, Pt, Pc]) ResetFn(index ocsd.TrcIndex) ocsd.DatapathResp {
	resp := ocsd.RespCont
	if pb.PktOutI.HasAttachedAndEnabled() {
		resp = pb.PktOutI.First().PacketDataIn(ocsd.OpReset, index, nil)
	}
	if !ocsd.DataRespIsFatal(resp) {
		if hook, ok := any(pb.strategy).(PktProcResetHook); ok {
			resp = hook.OnReset()
		}
	}
	if pb.PktRawMonI.HasAttachedAndEnabled() {
		pb.PktRawMonI.First().RawPacketDataMon(ocsd.OpReset, index, nil, nil)
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) Flush() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if pb.PktOutI.HasAttachedAndEnabled() {
		resp = pb.PktOutI.First().PacketDataIn(ocsd.OpFlush, 0, nil)
	}

	respLocal := ocsd.RespCont
	if ocsd.DataRespIsCont(resp) {
		if hook, ok := any(pb.strategy).(PktProcFlushHook); ok {
			respLocal = hook.OnFlush()
		}
	}

	if respLocal > resp {
		return respLocal
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) EOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if hook, ok := any(pb.strategy).(PktProcEOTHook); ok {
		resp = hook.OnEOT()
	}

	if pb.PktOutI.HasAttachedAndEnabled() && !ocsd.DataRespIsFatal(resp) {
		resp = pb.PktOutI.First().PacketDataIn(ocsd.OpEOT, 0, nil)
	}

	if pb.PktRawMonI.HasAttachedAndEnabled() {
		pb.PktRawMonI.First().RawPacketDataMon(ocsd.OpEOT, 0, nil, nil)
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) OutputDecodedPacket(indexSOP ocsd.TrcIndex, pkt *P) ocsd.DatapathResp {
	resp := ocsd.RespCont

	if (pb.ComponentOpMode() & ocsd.OpflgPktprocNofwdBadPkts) != 0 {
		if hook, ok := any(pb.strategy).(PktProcBadPacketHook); ok && hook.IsBadPacket() {
			return resp
		}
	}

	if pb.PktOutI.HasAttachedAndEnabled() {
		resp = pb.PktOutI.First().PacketDataIn(ocsd.OpData, indexSOP, pkt)
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) OutputRawPacketToMonitor(indexSOP ocsd.TrcIndex, pkt *P, pData []byte) {
	if len(pData) == 0 {
		return
	}
	if (pb.ComponentOpMode() & ocsd.OpflgPktprocNomonBadPkts) != 0 {
		if hook, ok := any(pb.strategy).(PktProcBadPacketHook); ok && hook.IsBadPacket() {
			return
		}
	}
	if pb.PktRawMonI.HasAttachedAndEnabled() {
		pb.PktRawMonI.First().RawPacketDataMon(ocsd.OpData, indexSOP, pkt, pData)
	}
}

func (pb *PktProcBase[P, Pt, Pc]) IndexPacket(indexSOP ocsd.TrcIndex, pktType Pt) {
	if pb.PktIndexerI.HasAttachedAndEnabled() {
		pb.PktIndexerI.First().TracePktIndex(indexSOP, pktType)
	}
}

func (pb *PktProcBase[P, Pt, Pc]) OutputOnAllInterfaces(indexSOP ocsd.TrcIndex, pkt *P, pktType Pt, pktData []byte) ocsd.DatapathResp {
	pb.IndexPacket(indexSOP, pktType)
	if len(pktData) > 0 {
		pb.OutputRawPacketToMonitor(indexSOP, pkt, pktData)
	}
	return pb.OutputDecodedPacket(indexSOP, pkt)
}

func (pb *PktProcBase[P, Pt, Pc]) SetProtocolConfig(config *Pc) ocsd.Err {
	if config != nil {
		pb.Config = config
		if hook, ok := any(pb.strategy).(PktProcProtocolConfigHook); ok {
			return hook.OnProtocolConfig()
		}
		return ocsd.OK
	}
	return ocsd.ErrInvalidParamVal
}

func (pb *PktProcBase[P, Pt, Pc]) GetStatsBlock() (*ocsd.DecodeStats, ocsd.Err) {
	if !pb.statsInit {
		return &pb.Stats, ocsd.ErrNotInit
	}
	return &pb.Stats, ocsd.OK
}

func (pb *PktProcBase[P, Pt, Pc]) HasRawMon() bool {
	return pb.PktRawMonI.HasAttachedAndEnabled()
}

func (pb *PktProcBase[P, Pt, Pc]) ResetStats() {
	pb.Stats.Version = ocsd.VerNum
	pb.Stats.Revision = ocsd.StatsRevision
	pb.Stats.ChannelTotal = 0
	pb.Stats.ChannelUnsynced = 0
	pb.Stats.BadHeaderErrs = 0
	pb.Stats.BadSequenceErrs = 0
	pb.Stats.Demux.FrameBytes = 0
	pb.Stats.Demux.NoIDBytes = 0
	pb.Stats.Demux.ValidIDBytes = 0
}

func (pb *PktProcBase[P, Pt, Pc]) StatsAddTotalCount(count uint64) { pb.Stats.ChannelTotal += count }
func (pb *PktProcBase[P, Pt, Pc]) StatsAddUnsyncCount(count uint64) {
	pb.Stats.ChannelUnsynced += count
}
func (pb *PktProcBase[P, Pt, Pc]) StatsAddBadSeqCount(count uint32) {
	pb.Stats.BadSequenceErrs += count
}
func (pb *PktProcBase[P, Pt, Pc]) StatsAddBadHdrCount(count uint32) { pb.Stats.BadHeaderErrs += count }
func (pb *PktProcBase[P, Pt, Pc]) StatsInit()                       { pb.statsInit = true }
