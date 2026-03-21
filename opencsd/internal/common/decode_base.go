package common

import (
	
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
type PktDecodeTraceIDProvider interface{ TraceID() uint8 }

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

	TraceElemOut AttachPt[ocsd.TrcGenElemIn]
	MemAccess    AttachPt[TargetMemAccess]
	InstrDecode  AttachPt[InstrDecode]

	IndexCurrPkt ocsd.TrcIndex

	configInitOK  bool
	usesMemAccess bool
	usesIDecode   bool

	traceIDProvider PktDecodeTraceIDProvider
}

func (p *PktDecodeI) TraceElemOutAttachPt() *AttachPt[ocsd.TrcGenElemIn] {
	return &p.TraceElemOut
}
func (p *PktDecodeI) InstrDecodeAttachPt() *AttachPt[InstrDecode] { return &p.InstrDecode }
func (p *PktDecodeI) MemAccAttachPt() *AttachPt[TargetMemAccess]  { return &p.MemAccess }

func (p *PktDecodeI) SetUsesMemAccess(uses bool) { p.usesMemAccess = uses }
func (p *PktDecodeI) UsesMemAccess() bool     { return p.usesMemAccess }

func (p *PktDecodeI) SetUsesIDecode(uses bool) { p.usesIDecode = uses }
func (p *PktDecodeI) UsesIDecode() bool     { return p.usesIDecode }

func (p *PktDecodeI) decodeNotReadyReason() string {
	if !p.configInitOK {
		return "No decoder configuration information"
	}
	if !p.TraceElemOut.HasAttachedAndEnabled() {
		return "No element output interface attached and enabled"
	}
	if p.usesMemAccess && !p.MemAccess.HasAttachedAndEnabled() {
		return "No memory access interface attached and enabled"
	}
	if p.usesIDecode && !p.InstrDecode.HasAttachedAndEnabled() {
		return "No instruction decoder interface attached and enabled"
	}

	return ""
}

func (p *PktDecodeI) OutputTraceElement(elem *ocsd.TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.HasAttachedAndEnabled() && p.traceIDProvider != nil {
		return p.TraceElemOut.First().TraceElemIn(p.IndexCurrPkt, p.traceIDProvider.TraceID(), elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) OutputTraceElementIdx(idx ocsd.TrcIndex, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.HasAttachedAndEnabled() && p.traceIDProvider != nil {
		return p.TraceElemOut.First().TraceElemIn(idx, p.traceIDProvider.TraceID(), elem)
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
			return p.MemAccess.First().ReadTargetMemory(address, p.traceIDProvider.TraceID(), memSpace, reqBytes)
		}
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) InvalidateMemAccCache() ocsd.Err {
	if !p.usesMemAccess {
		return ocsd.ErrDcdInterfaceUnused
	}
	if p.MemAccess.HasAttachedAndEnabled() && p.traceIDProvider != nil {
		p.MemAccess.First().InvalidateMemAccCache(p.traceIDProvider.TraceID())
	}
	return ocsd.OK
}

// PktDecodeBase represents TrcPktDecodeBase<P, Pc>.
type PktDecodeBase[P any, Pc any] struct {
	PktDecodeI
	Config             *Pc
	CurrPacketIn       *P
	strategy           PktDecodeStrategy[P, Pc]
	eotHook            PktDecodeEOTHook
	resetHook          PktDecodeResetHook
	flushHook          PktDecodeFlushHook
	protocolConfigHook PktDecodeProtocolConfigHook
}

func (pb *PktDecodeBase[P, Pc]) InitPktDecodeBase(name string) {
	pb.InitTraceComponent(name)
	pb.TraceElemOut = *NewAttachPt[ocsd.TrcGenElemIn]()
	pb.MemAccess = *NewAttachPt[TargetMemAccess]()
	pb.InstrDecode = *NewAttachPt[InstrDecode]()
	pb.usesMemAccess = true
	pb.usesIDecode = true
}

func (pb *PktDecodeBase[P, Pc]) SetStrategy(strategy PktDecodeStrategy[P, Pc]) {
	pb.strategy = strategy
	pb.traceIDProvider = nil
	pb.eotHook = nil
	pb.resetHook = nil
	pb.flushHook = nil
	pb.protocolConfigHook = nil
	if strategy == nil {
		return
	}
	if traceIDProvider, ok := any(strategy).(PktDecodeTraceIDProvider); ok {
		pb.traceIDProvider = traceIDProvider
	}
	if hook, ok := any(strategy).(PktDecodeEOTHook); ok {
		pb.eotHook = hook
	}
	if hook, ok := any(strategy).(PktDecodeResetHook); ok {
		pb.resetHook = hook
	}
	if hook, ok := any(strategy).(PktDecodeFlushHook); ok {
		pb.flushHook = hook
	}
	if hook, ok := any(strategy).(PktDecodeProtocolConfigHook); ok {
		pb.protocolConfigHook = hook
	}
}

func (pb *PktDecodeBase[P, Pc]) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *P) ocsd.DatapathResp {
	resp := ocsd.RespCont
	if reason := pb.decodeNotReadyReason(); reason != "" {
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
		if pb.eotHook != nil {
			resp = pb.eotHook.OnEOT()
		}
	case ocsd.OpFlush:
		if pb.flushHook != nil {
			resp = pb.flushHook.OnFlush()
		}
	case ocsd.OpReset:
		if pb.resetHook != nil {
			resp = pb.resetHook.OnReset()
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
		if pb.protocolConfigHook != nil {
			err := pb.protocolConfigHook.OnProtocolConfig()
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

// PktProcBase represents TrcPktProcBase<P, Pt, Pc>.
type PktProcBase[P any, Pt any, Pc any] struct {
	PktProcI
	Config             *Pc
	PktOutI            AttachPt[PktDataIn[P]]
	PktRawMonI         AttachPt[PktRawDataMon[P]]
	PktIndexerI        AttachPt[TrcPktIndexer[Pt]]
	Stats              ocsd.DecodeStats
	statsInit          bool
	strategy           PktProcStrategy[P, Pt, Pc]
	eotHook            PktProcEOTHook
	resetHook          PktProcResetHook
	flushHook          PktProcFlushHook
	protocolConfigHook PktProcProtocolConfigHook
	badPacketHook      PktProcBadPacketHook
}

func (pb *PktProcBase[P, Pt, Pc]) InitPktProcBase(name string) {
	pb.InitTraceComponent(name)
	pb.PktOutI = *NewAttachPt[PktDataIn[P]]()
	pb.PktRawMonI = *NewAttachPt[PktRawDataMon[P]]()
	pb.PktIndexerI = *NewAttachPt[TrcPktIndexer[Pt]]()
	pb.ResetStats()
}

func (pb *PktProcBase[P, Pt, Pc]) SetStrategy(strategy PktProcStrategy[P, Pt, Pc]) {
	pb.strategy = strategy
	pb.eotHook = nil
	pb.resetHook = nil
	pb.flushHook = nil
	pb.protocolConfigHook = nil
	pb.badPacketHook = nil
	if strategy == nil {
		return
	}
	if hook, ok := any(strategy).(PktProcEOTHook); ok {
		pb.eotHook = hook
	}
	if hook, ok := any(strategy).(PktProcResetHook); ok {
		pb.resetHook = hook
	}
	if hook, ok := any(strategy).(PktProcFlushHook); ok {
		pb.flushHook = hook
	}
	if hook, ok := any(strategy).(PktProcProtocolConfigHook); ok {
		pb.protocolConfigHook = hook
	}
	if hook, ok := any(strategy).(PktProcBadPacketHook); ok {
		pb.badPacketHook = hook
	}
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
		if pb.resetHook != nil {
			resp = pb.resetHook.OnReset()
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
		if pb.flushHook != nil {
			respLocal = pb.flushHook.OnFlush()
		}
	}

	if respLocal > resp {
		return respLocal
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) EOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if pb.eotHook != nil {
		resp = pb.eotHook.OnEOT()
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
		if pb.badPacketHook != nil && pb.badPacketHook.IsBadPacket() {
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
		if pb.badPacketHook != nil && pb.badPacketHook.IsBadPacket() {
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
		if pb.protocolConfigHook != nil {
			return pb.protocolConfigHook.OnProtocolConfig()
		}
		return ocsd.OK
	}
	return ocsd.ErrInvalidParamVal
}

func (pb *PktProcBase[P, Pt, Pc]) StatsBlock() (*ocsd.DecodeStats, ocsd.Err) {
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
