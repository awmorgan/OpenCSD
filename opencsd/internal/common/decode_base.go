package common

import (
	"opencsd/internal/ocsd"
)

// TrcGenElemIn represents ITrcGenElemIn.
// Interface for the input of generic trace elements.
type TrcGenElemIn interface {
	TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *TraceElement) ocsd.DatapathResp
}

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

// PktDecodeI represents TrcPktDecodeI.
type PktDecodeI struct {
	TraceComponent

	TraceElemOut AttachPt[TrcGenElemIn]
	MemAccess    AttachPt[TargetMemAccess]
	InstrDecode  AttachPt[InstrDecode]

	IndexCurrPkt ocsd.TrcIndex

	decodeInitOK  bool
	configInitOK  bool
	initErrMsg    string
	usesMemAccess bool
	usesIDecode   bool

	// Functions to be implemented by derived structures
	FnProcessPacket    func() ocsd.DatapathResp
	FnOnEOT            func() ocsd.DatapathResp
	FnOnReset          func() ocsd.DatapathResp
	FnOnFlush          func() ocsd.DatapathResp
	FnOnProtocolConfig func() ocsd.Err
	FnGetTraceID       func() uint8
	FnOnFirstInitOK    func()
}

func (p *PktDecodeI) InitPktDecodeI(name string) {
	p.InitTraceComponent(name)
	p.TraceElemOut = *NewAttachPt[TrcGenElemIn]()
	p.MemAccess = *NewAttachPt[TargetMemAccess]()
	p.InstrDecode = *NewAttachPt[InstrDecode]()
	p.usesMemAccess = true
	p.usesIDecode = true
}

func (p *PktDecodeI) SetUsesMemAccess(uses bool) { p.usesMemAccess = uses }
func (p *PktDecodeI) GetUsesMemAccess() bool     { return p.usesMemAccess }

func (p *PktDecodeI) SetUsesIDecode(uses bool) { p.usesIDecode = uses }
func (p *PktDecodeI) GetUsesIDecode() bool     { return p.usesIDecode }

func (p *PktDecodeI) CheckInit() bool {
	if !p.decodeInitOK {
		if !p.configInitOK {
			p.initErrMsg = "No decoder configuration information"
		} else if !p.TraceElemOut.HasAttachedAndEnabled() {
			p.initErrMsg = "No element output interface attached and enabled"
		} else if p.usesMemAccess && !p.MemAccess.HasAttachedAndEnabled() {
			p.initErrMsg = "No memory access interface attached and enabled"
		} else if p.usesIDecode && !p.InstrDecode.HasAttachedAndEnabled() {
			p.initErrMsg = "No instruction decoder interface attached and enabled"
		} else {
			p.decodeInitOK = true
		}
		if p.decodeInitOK && p.FnOnFirstInitOK != nil {
			p.FnOnFirstInitOK()
		}
	}
	return p.decodeInitOK
}

func (p *PktDecodeI) OutputTraceElement(elem *TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.HasAttachedAndEnabled() && p.FnGetTraceID != nil {
		return p.TraceElemOut.First().TraceElemIn(p.IndexCurrPkt, p.FnGetTraceID(), elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) OutputTraceElementIdx(idx ocsd.TrcIndex, elem *TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.HasAttachedAndEnabled() && p.FnGetTraceID != nil {
		return p.TraceElemOut.First().TraceElemIn(idx, p.FnGetTraceID(), elem)
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
		if p.MemAccess.HasAttachedAndEnabled() && p.FnGetTraceID != nil {
			return p.MemAccess.First().ReadTargetMemory(address, p.FnGetTraceID(), memSpace, reqBytes)
		}
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) InvalidateMemAccCache() ocsd.Err {
	if !p.usesMemAccess {
		return ocsd.ErrDcdInterfaceUnused
	}
	if p.MemAccess.HasAttachedAndEnabled() && p.FnGetTraceID != nil {
		p.MemAccess.First().InvalidateMemAccCache(p.FnGetTraceID())
	}
	return ocsd.OK
}

// PktDecodeBase represents TrcPktDecodeBase<P, Pc>.
type PktDecodeBase[P any, Pc any] struct {
	PktDecodeI
	Config       *Pc
	CurrPacketIn *P
}

func (pb *PktDecodeBase[P, Pc]) InitPktDecodeBase(name string) {
	pb.InitPktDecodeI(name)
}

func (pb *PktDecodeBase[P, Pc]) PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pktIn *P) ocsd.DatapathResp {
	resp := ocsd.RespCont
	if !pb.CheckInit() {
		pb.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrNotInit, pb.initErrMsg))
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
			if pb.FnProcessPacket != nil {
				resp = pb.FnProcessPacket()
			}
		}
	case ocsd.OpEOT:
		if pb.FnOnEOT != nil {
			resp = pb.FnOnEOT()
		}
	case ocsd.OpFlush:
		if pb.FnOnFlush != nil {
			resp = pb.FnOnFlush()
		}
	case ocsd.OpReset:
		if pb.FnOnReset != nil {
			resp = pb.FnOnReset()
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
		if pb.FnOnProtocolConfig != nil {
			err := pb.FnOnProtocolConfig()
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

	FnProcessData      func(index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp)
	FnOnEOT            func() ocsd.DatapathResp
	FnOnReset          func() ocsd.DatapathResp
	FnOnFlush          func() ocsd.DatapathResp
	FnOnProtocolConfig func() ocsd.Err
	FnIsBadPacket      func() bool
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
	isInit      bool
}

func (pb *PktProcBase[P, Pt, Pc]) InitPktProcBase(name string) {
	pb.InitPktProcI(name)
	pb.PktOutI = *NewAttachPt[PktDataIn[P]]()
	pb.PktRawMonI = *NewAttachPt[PktRawDataMon[P]]()
	pb.PktIndexerI = *NewAttachPt[TrcPktIndexer[Pt]]()
	pb.ResetStats()
}

func (pb *PktProcBase[P, Pt, Pc]) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp) {
	resp := ocsd.RespCont
	var processed uint32 = 0

	switch op {
	case ocsd.OpData:
		if len(dataBlock) == 0 {
			pb.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "Packet Processor: Zero length data block error"))
			resp = ocsd.RespFatalInvalidParam
		} else {
			if pb.FnProcessData != nil {
				processed, resp = pb.FnProcessData(index, dataBlock)
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
	return processed, resp
}

func (pb *PktProcBase[P, Pt, Pc]) ResetFn(index ocsd.TrcIndex) ocsd.DatapathResp {
	resp := ocsd.RespCont
	if pb.PktOutI.HasAttachedAndEnabled() {
		resp = pb.PktOutI.First().PacketDataIn(ocsd.OpReset, index, nil)
	}
	if !ocsd.DataRespIsFatal(resp) && pb.FnOnReset != nil {
		resp = pb.FnOnReset()
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
	if ocsd.DataRespIsCont(resp) && pb.FnOnFlush != nil {
		respLocal = pb.FnOnFlush()
	}

	if respLocal > resp {
		return respLocal
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) EOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if pb.FnOnEOT != nil {
		resp = pb.FnOnEOT()
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

	if (pb.ComponentOpMode()&ocsd.OpflgPktprocNofwdBadPkts != 0) && pb.FnIsBadPacket != nil && pb.FnIsBadPacket() {
		return resp
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
	if (pb.ComponentOpMode()&ocsd.OpflgPktprocNomonBadPkts != 0) && pb.FnIsBadPacket != nil && pb.FnIsBadPacket() {
		return
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
		if pb.FnOnProtocolConfig != nil {
			return pb.FnOnProtocolConfig()
		}
		return ocsd.OK
	}
	return ocsd.ErrInvalidParamVal
}

func (pb *PktProcBase[P, Pt, Pc]) CheckInit() bool {
	if !pb.isInit {
		if pb.Config != nil && (pb.PktOutI.HasAttached() || pb.PktRawMonI.HasAttached()) {
			pb.isInit = true
		}
	}
	return pb.isInit
}

func (pb *PktProcBase[P, Pt, Pc]) GetStatsBlock() (*ocsd.DecodeStats, ocsd.Err) {
	if !pb.statsInit {
		return &pb.Stats, ocsd.ErrNotInit
	}
	return &pb.Stats, ocsd.OK
}

func (pb *PktProcBase[P, Pt, Pc]) ResetStats() {
	pb.Stats.Version = 0
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
