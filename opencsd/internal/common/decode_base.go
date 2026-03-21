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

// PktDecodeI represents TrcPktDecodeI.
type PktDecodeI struct {
	TraceComponent

	TraceElemOut AttachPt[ocsd.TrcGenElemIn]
	MemAccess    AttachPt[TargetMemAccess]
	InstrDecode  AttachPt[InstrDecode]

	IndexCurrPkt ocsd.TrcIndex

	ConfigInitOK  bool
	usesMemAccess bool
	usesIDecode   bool
}

func (p *PktDecodeI) TraceElemOutAttachPt() *AttachPt[ocsd.TrcGenElemIn] {
	return &p.TraceElemOut
}
func (p *PktDecodeI) InstrDecodeAttachPt() *AttachPt[InstrDecode] { return &p.InstrDecode }
func (p *PktDecodeI) MemAccAttachPt() *AttachPt[TargetMemAccess]  { return &p.MemAccess }

func (p *PktDecodeI) SetNeedsMemAccess(needs bool) { p.usesMemAccess = needs }
func (p *PktDecodeI) NeedsMemAccess() bool         { return p.usesMemAccess }

func (p *PktDecodeI) SetNeedsInstructionDecode(needs bool) { p.usesIDecode = needs }
func (p *PktDecodeI) NeedsInstructionDecode() bool         { return p.usesIDecode }

func (p *PktDecodeI) DecodeNotReadyReason() string {
	if !p.ConfigInitOK {
		return "No decoder configuration information"
	}
	if !p.TraceElemOut.IsActive() {
		return "No element output interface attached and enabled"
	}
	if p.usesMemAccess && !p.MemAccess.IsActive() {
		return "No memory access interface attached and enabled"
	}
	if p.usesIDecode && !p.InstrDecode.IsActive() {
		return "No instruction decoder interface attached and enabled"
	}

	return ""
}

func (p *PktDecodeI) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.IsActive() {
		return p.TraceElemOut.First().TraceElemIn(p.IndexCurrPkt, traceID, elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if p.TraceElemOut.IsActive() {
		return p.TraceElemOut.First().TraceElemIn(idx, traceID, elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) InstrDecodeCall(instrInfo *ocsd.InstrInfo) ocsd.Err {
	if p.usesIDecode {
		if p.InstrDecode.IsActive() {
			return p.InstrDecode.First().DecodeInstruction(instrInfo)
		}
	}
	return ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) AccessMemory(address ocsd.VAddr, traceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	if p.usesMemAccess {
		if p.MemAccess.IsActive() {
			return p.MemAccess.First().ReadTargetMemory(address, traceID, memSpace, reqBytes)
		}
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) InvalidateMemAccCache(traceID uint8) ocsd.Err {
	if !p.usesMemAccess {
		return ocsd.ErrDcdInterfaceUnused
	}
	if p.MemAccess.IsActive() {
		p.MemAccess.First().InvalidateMemAccCache(traceID)
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
	pb.InitTraceComponent(name)
	pb.TraceElemOut = *NewAttachPt[ocsd.TrcGenElemIn]()
	pb.MemAccess = *NewAttachPt[TargetMemAccess]()
	pb.InstrDecode = *NewAttachPt[InstrDecode]()
	pb.usesMemAccess = true
	pb.usesIDecode = true
}

// PktProcI represents TrcPktProcI.
type PktProcI struct {
	TraceComponent
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
}

func (pb *PktProcBase[P, Pt, Pc]) InitPktProcBase(name string) {
	pb.InitTraceComponent(name)
	pb.PktOutI = *NewAttachPt[PktDataIn[P]]()
	pb.PktRawMonI = *NewAttachPt[PktRawDataMon[P]]()
	pb.PktIndexerI = *NewAttachPt[TrcPktIndexer[Pt]]()
	pb.ResetStats()
}

func (pb *PktProcBase[P, Pt, Pc]) OutputDecodedPacket(indexSOP ocsd.TrcIndex, pkt *P) ocsd.DatapathResp {
	resp := ocsd.RespCont

	if pb.PktOutI.IsActive() {
		resp = pb.PktOutI.First().PacketDataIn(ocsd.OpData, indexSOP, pkt)
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) OutputRawPacketToMonitor(indexSOP ocsd.TrcIndex, pkt *P, pData []byte) {
	if len(pData) == 0 {
		return
	}
	if pb.PktRawMonI.IsActive() {
		pb.PktRawMonI.First().RawPacketDataMon(ocsd.OpData, indexSOP, pkt, pData)
	}
}

func (pb *PktProcBase[P, Pt, Pc]) IndexPacket(indexSOP ocsd.TrcIndex, pktType Pt) {
	if pb.PktIndexerI.IsActive() {
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

func (pb *PktProcBase[P, Pt, Pc]) StatsBlock() (*ocsd.DecodeStats, ocsd.Err) {
	if !pb.statsInit {
		return &pb.Stats, ocsd.ErrNotInit
	}
	return &pb.Stats, ocsd.OK
}

func (pb *PktProcBase[P, Pt, Pc]) HasRawMon() bool {
	return pb.PktRawMonI.IsActive()
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
