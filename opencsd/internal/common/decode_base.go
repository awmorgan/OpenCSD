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

// PktDecodeI represents TrcPktDecodeI.
type PktDecodeI struct {
	name             string
	opFlags          uint32
	supportedOpFlags uint32
	logger           ocsd.Logger
	errVerbosity     ocsd.ErrSeverity

	TraceElemOut ocsd.GenElemProcessor
	MemAccess    TargetMemAccess
	InstrDecode  InstrDecode

	IndexCurrPkt ocsd.TrcIndex

	ConfigInitOK  bool
	usesMemAccess bool
	usesIDecode   bool
}

func (p *PktDecodeI) Init(name string, logger ocsd.Logger) {
	p.name = name
	p.logger = logger
	p.errVerbosity = ocsd.ErrSevNone
	p.usesMemAccess = true
	p.usesIDecode = true
}

func (p *PktDecodeI) ComponentName() string { return p.name }

func (p *PktDecodeI) ConfigureComponentOpMode(opFlags uint32) ocsd.Err {
	p.opFlags = opFlags & p.supportedOpFlags
	return ocsd.OK
}

func (p *PktDecodeI) ComponentOpMode() uint32 { return p.opFlags }

func (p *PktDecodeI) SupportedOpModes() uint32 { return p.supportedOpFlags }

func (p *PktDecodeI) ConfigureSupportedOpModes(flags uint32) { p.supportedOpFlags = flags }

func (p *PktDecodeI) AttachErrorLogger(logger ocsd.Logger) ocsd.Err {
	if p.logger != nil {
		return ocsd.ErrAttachTooMany
	}
	p.logger = logger
	return ocsd.OK
}

func (p *PktDecodeI) DetachErrorLogger() ocsd.Err {
	if p.logger == nil {
		return ocsd.ErrAttachCompNotFound
	}
	p.logger = nil
	return ocsd.OK
}

func (p *PktDecodeI) LogDefMessage(msg string) { p.LogMessage(p.errVerbosity, msg) }

func (p *PktDecodeI) LogError(err *Error) {
	if err == nil {
		return
	}
	if p.logger != nil && p.IsLoggingErrorLevel(err.Sev) {
		p.logger.LogError(err.Sev, err)
	}
}

func (p *PktDecodeI) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	if filterLevel <= p.errVerbosity && p.logger != nil {
		p.logger.LogMessage(filterLevel, msg)
	}
}

func (p *PktDecodeI) ErrorLogLevel() ocsd.ErrSeverity { return p.errVerbosity }

func (p *PktDecodeI) IsLoggingErrorLevel(level ocsd.ErrSeverity) bool {
	return level <= p.errVerbosity
}

func (p *PktDecodeI) ConfigureErrorLogLevel(level ocsd.ErrSeverity) {
	p.errVerbosity = level
}

func (p *PktDecodeI) SetTraceElemOut(out ocsd.GenElemProcessor) {
	p.TraceElemOut = out
}

func (p *PktDecodeI) TraceElemOutIf() ocsd.GenElemProcessor {
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

// PktProcI represents TrcPktProcI.
type PktProcI struct {
	name             string
	opFlags          uint32
	supportedOpFlags uint32
	logger           ocsd.Logger
	errVerbosity     ocsd.ErrSeverity
}

func (p *PktProcI) Init(name string, logger ocsd.Logger) {
	p.name = name
	p.logger = logger
	p.errVerbosity = ocsd.ErrSevNone
}

func (p *PktProcI) ComponentName() string { return p.name }

func (p *PktProcI) ConfigureComponentOpMode(opFlags uint32) ocsd.Err {
	p.opFlags = opFlags & p.supportedOpFlags
	return ocsd.OK
}

func (p *PktProcI) ComponentOpMode() uint32 { return p.opFlags }

func (p *PktProcI) SupportedOpModes() uint32 { return p.supportedOpFlags }

func (p *PktProcI) ConfigureSupportedOpModes(flags uint32) { p.supportedOpFlags = flags }

func (p *PktProcI) AttachErrorLogger(logger ocsd.Logger) ocsd.Err {
	if p.logger != nil {
		return ocsd.ErrAttachTooMany
	}
	p.logger = logger
	return ocsd.OK
}

func (p *PktProcI) DetachErrorLogger() ocsd.Err {
	if p.logger == nil {
		return ocsd.ErrAttachCompNotFound
	}
	p.logger = nil
	return ocsd.OK
}

func (p *PktProcI) LogDefMessage(msg string) { p.LogMessage(p.errVerbosity, msg) }

func (p *PktProcI) LogError(err *Error) {
	if err == nil {
		return
	}
	if p.logger != nil && p.IsLoggingErrorLevel(err.Sev) {
		p.logger.LogError(err.Sev, err)
	}
}

func (p *PktProcI) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	if filterLevel <= p.errVerbosity && p.logger != nil {
		p.logger.LogMessage(filterLevel, msg)
	}
}

func (p *PktProcI) ErrorLogLevel() ocsd.ErrSeverity { return p.errVerbosity }

func (p *PktProcI) IsLoggingErrorLevel(level ocsd.ErrSeverity) bool {
	return level <= p.errVerbosity
}

func (p *PktProcI) ConfigureErrorLogLevel(level ocsd.ErrSeverity) {
	p.errVerbosity = level
}

// PktProcBase represents TrcPktProcBase<P, Pt, Pc>.
type PktProcBase[P any, Pt any, Pc any] struct {
	PktProcI
	Config      *Pc
	PktOutI     ocsd.PacketProcessor[P]
	PktRawMonI  ocsd.PacketMonitor[P]
	PktIndexerI TrcPktIndexer[Pt]
	Stats       ocsd.DecodeStats
	statsInit   bool
}

func (pb *PktProcBase[P, Pt, Pc]) ConfigurePktProcBase(name string) {
	pb.PktProcI.Init(name, nil)
	pb.ResetStats()
}

func (pb *PktProcBase[P, Pt, Pc]) SetPktOut(out ocsd.PacketProcessor[P]) {
	pb.PktOutI = out
}

func (pb *PktProcBase[P, Pt, Pc]) PktOut() ocsd.PacketProcessor[P] {
	return pb.PktOutI
}

func (pb *PktProcBase[P, Pt, Pc]) SetPktRawMonitor(mon ocsd.PacketMonitor[P]) {
	pb.PktRawMonI = mon
}

func (pb *PktProcBase[P, Pt, Pc]) PktRawMonitor() ocsd.PacketMonitor[P] {
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
