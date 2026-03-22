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

// PktDataIn aliases the canonical packet input interface.
type PktDataIn[P any] = ocsd.PktDataIn[P]

// PktRawDataMon aliases the canonical raw packet monitor interface.
type PktRawDataMon[P any] = ocsd.PktRawDataMon[P]

// PktDecodeI represents TrcPktDecodeI.
type PktDecodeI struct {
	TraceComponent

	TraceElemOut ocsd.TrcGenElemIn
	MemAccess    TargetMemAccess
	InstrDecode  InstrDecode

	IndexCurrPkt ocsd.TrcIndex

	ConfigInitOK  bool
	usesMemAccess bool
	usesIDecode   bool
}

func (p *PktDecodeI) SetTraceElemOut(out ocsd.TrcGenElemIn) {
	p.TraceElemOut = out
}

func (p *PktDecodeI) TraceElemOutIf() ocsd.TrcGenElemIn {
	return p.TraceElemOut
}

func (p *PktDecodeI) SetMemAccess(mem TargetMemAccess) {
	p.MemAccess = mem
}

func (p *PktDecodeI) MemAccessIf() TargetMemAccess {
	return p.MemAccess
}

func (p *PktDecodeI) SetInstrDecode(decoder InstrDecode) {
	p.InstrDecode = decoder
}

func (p *PktDecodeI) InstrDecodeIf() InstrDecode {
	return p.InstrDecode
}

func (p *PktDecodeI) SetNeedsMemAccess(needs bool) { p.usesMemAccess = needs }
func (p *PktDecodeI) NeedsMemAccess() bool         { return p.usesMemAccess }

func (p *PktDecodeI) SetNeedsInstructionDecode(needs bool) { p.usesIDecode = needs }
func (p *PktDecodeI) NeedsInstructionDecode() bool         { return p.usesIDecode }

func (p *PktDecodeI) DecodeNotReadyReason() string {
	if !p.ConfigInitOK {
		return "No decoder configuration information"
	}
	if p.TraceElemOutIf() == nil {
		return "No element output interface attached and enabled"
	}
	if p.usesMemAccess && p.MemAccessIf() == nil {
		return "No memory access interface attached and enabled"
	}
	if p.usesIDecode && p.InstrDecodeIf() == nil {
		return "No instruction decoder interface attached and enabled"
	}

	return ""
}

func (p *PktDecodeI) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if out := p.TraceElemOutIf(); out != nil {
		return out.TraceElemIn(p.IndexCurrPkt, traceID, elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if out := p.TraceElemOutIf(); out != nil {
		return out.TraceElemIn(idx, traceID, elem)
	}
	return ocsd.RespFatalNotInit
}

func (p *PktDecodeI) InstrDecodeCall(instrInfo *ocsd.InstrInfo) ocsd.Err {
	if p.usesIDecode {
		if decoder := p.InstrDecodeIf(); decoder != nil {
			return decoder.DecodeInstruction(instrInfo)
		}
	}
	return ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) AccessMemory(address ocsd.VAddr, traceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	if p.usesMemAccess {
		if mem := p.MemAccessIf(); mem != nil {
			return mem.ReadTargetMemory(address, traceID, memSpace, reqBytes)
		}
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

func (p *PktDecodeI) InvalidateMemAccCache(traceID uint8) ocsd.Err {
	if !p.usesMemAccess {
		return ocsd.ErrDcdInterfaceUnused
	}
	if mem := p.MemAccessIf(); mem != nil {
		mem.InvalidateMemAccCache(traceID)
	}
	return ocsd.OK
}

// PktDecodeBase represents TrcPktDecodeBase<P, Pc>.
type PktDecodeBase[P any, Pc any] struct {
	PktDecodeI
	Config       *Pc
	CurrPacketIn *P
}

func (pb *PktDecodeBase[P, Pc]) ConfigurePktDecodeBase(name string) {
	pb.ConfigureTraceComponent(name)
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
	PktOutI     PktDataIn[P]
	PktRawMonI  PktRawDataMon[P]
	PktIndexerI TrcPktIndexer[Pt]
	Stats       ocsd.DecodeStats
	statsInit   bool
}

func (pb *PktProcBase[P, Pt, Pc]) ConfigurePktProcBase(name string) {
	pb.ConfigureTraceComponent(name)
	pb.ResetStats()
}

func (pb *PktProcBase[P, Pt, Pc]) SetPktOut(out PktDataIn[P]) {
	pb.PktOutI = out
}

func (pb *PktProcBase[P, Pt, Pc]) PktOut() PktDataIn[P] {
	return pb.PktOutI
}

func (pb *PktProcBase[P, Pt, Pc]) SetPktRawMonitor(mon PktRawDataMon[P]) {
	pb.PktRawMonI = mon
}

func (pb *PktProcBase[P, Pt, Pc]) PktRawMonitor() PktRawDataMon[P] {
	return pb.PktRawMonI
}

func (pb *PktProcBase[P, Pt, Pc]) SetPktIndexer(indexer TrcPktIndexer[Pt]) {
	pb.PktIndexerI = indexer
}

func (pb *PktProcBase[P, Pt, Pc]) PktIndexer() TrcPktIndexer[Pt] {
	return pb.PktIndexerI
}

func (pb *PktProcBase[P, Pt, Pc]) OutputDecodedPacket(indexSOP ocsd.TrcIndex, pkt *P) ocsd.DatapathResp {
	resp := ocsd.RespCont

	if out := pb.PktOut(); out != nil {
		resp = out.PacketDataIn(ocsd.OpData, indexSOP, pkt)
	}
	return resp
}

func (pb *PktProcBase[P, Pt, Pc]) OutputRawPacketToMonitor(indexSOP ocsd.TrcIndex, pkt *P, pData []byte) {
	if len(pData) == 0 {
		return
	}
	if rawMon := pb.PktRawMonitor(); rawMon != nil {
		rawMon.RawPacketDataMon(ocsd.OpData, indexSOP, pkt, pData)
	}
}

func (pb *PktProcBase[P, Pt, Pc]) IndexPacket(indexSOP ocsd.TrcIndex, pktType Pt) {
	if indexer := pb.PktIndexer(); indexer != nil {
		indexer.TracePktIndex(indexSOP, pktType)
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
	return pb.PktRawMonitor() != nil
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
