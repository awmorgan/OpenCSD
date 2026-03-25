package common

import (
	"opencsd/internal/ocsd"
)

// TargetMemAccess represents ITargetMemAccess.
// Interface to memory access.
type TargetMemAccess interface {
	ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error)
	InvalidateMemAccCache(csTraceID uint8)
}

// InstrDecode represents IInstrDecode.
// Interface to instruction decoding.
type InstrDecode interface {
	DecodeInstruction(instrInfo *ocsd.InstrInfo) error
}

// TrcPktIndexer represents ITrcPktIndexer.
// Interface designed to allow tracing of packets back to the source data stream.
type TrcPktIndexer[Pt any] interface {
	TracePktIndex(indexSOP ocsd.TrcIndex, pktType Pt)
}

// DecoderBase holds the shared state for a packet decoder.
// Concrete decoders hold it as a named field (e.g. Base DecoderBase) and
// call its methods explicitly — no embedding, no promoted method surface.
type DecoderBase struct {
	Name             string
	Logger           ocsd.Logger
	ErrVerbosity     ocsd.ErrSeverity
	OpFlags          uint32
	SupportedOpFlags uint32

	TraceElemOut ocsd.GenElemProcessor
	MemAccess    TargetMemAccess
	InstrDecode  InstrDecode

	IndexCurrPkt  ocsd.TrcIndex
	ConfigInitOK  bool
	UsesMemAccess bool
	UsesIDecode   bool
}

// Init sets up the DecoderBase with a component name and optional logger.
func (b *DecoderBase) Init(name string, logger ocsd.Logger) {
	b.Name = name
	b.Logger = logger
	b.ErrVerbosity = ocsd.ErrSevNone
	b.UsesMemAccess = true
	b.UsesIDecode = true
}

// LogError logs an error if the logger is set and the severity threshold is met.
func (b *DecoderBase) LogError(sev ocsd.ErrSeverity, err error) {
	if err == nil {
		return
	}
	if b.Logger != nil && b.IsLoggingErrorLevel(sev) {
		b.Logger.LogError(sev, err)
	}
}

// LogMessage logs a message at the given severity level.
func (b *DecoderBase) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	if filterLevel <= b.ErrVerbosity && b.Logger != nil {
		b.Logger.LogMessage(filterLevel, msg)
	}
}

// IsLoggingErrorLevel reports whether errors at the given severity should be logged.
func (b *DecoderBase) IsLoggingErrorLevel(level ocsd.ErrSeverity) bool {
	return level <= b.ErrVerbosity
}

// ConfigureComponentOpMode applies opFlags masked to the supported set.
func (b *DecoderBase) ConfigureComponentOpMode(opFlags uint32) error {
	b.OpFlags = opFlags & b.SupportedOpFlags
	return nil
}

// ComponentOpMode returns the current operational mode flags.
func (b *DecoderBase) ComponentOpMode() uint32 { return b.OpFlags }

// SupportedOpModes returns the supported operational mode bitmask.
func (b *DecoderBase) SupportedOpModes() uint32 { return b.SupportedOpFlags }

// ConfigureSupportedOpModes sets which op-mode flags this decoder supports.
func (b *DecoderBase) ConfigureSupportedOpModes(flags uint32) { b.SupportedOpFlags = flags }

// OutputTraceElement sends an element to the downstream consumer using IndexCurrPkt.
func (b *DecoderBase) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if b.TraceElemOut != nil {
		return b.TraceElemOut.TraceElemIn(b.IndexCurrPkt, traceID, elem)
	}
	return ocsd.RespFatalNotInit
}

// OutputTraceElementIdx sends an element to the downstream consumer at an explicit index.
func (b *DecoderBase) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	if b.TraceElemOut != nil {
		return b.TraceElemOut.TraceElemIn(idx, traceID, elem)
	}
	return ocsd.RespFatalNotInit
}

// DecodeNotReadyReason returns a human-readable explanation of why the decoder is not
// ready, or an empty string if the decoder is ready to process packets.
func (b *DecoderBase) DecodeNotReadyReason() string {
	if !b.ConfigInitOK {
		return "No decoder configuration information"
	}
	if b.TraceElemOut == nil {
		return "No element output interface attached and enabled"
	}
	if b.UsesMemAccess && b.MemAccess == nil {
		return "No memory access interface attached and enabled"
	}
	if b.UsesIDecode && b.InstrDecode == nil {
		return "No instruction decoder interface attached and enabled"
	}
	return ""
}

// AccessMemory reads target memory via the attached TargetMemAccess interface.
func (b *DecoderBase) AccessMemory(address ocsd.VAddr, traceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	if b.UsesMemAccess {
		if b.MemAccess != nil {
			return b.MemAccess.ReadTargetMemory(address, traceID, memSpace, reqBytes)
		}
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

// InstrDecodeCall calls the attached instruction decoder.
func (b *DecoderBase) InstrDecodeCall(instrInfo *ocsd.InstrInfo) error {
	if b.UsesIDecode {
		if b.InstrDecode != nil {
			return b.InstrDecode.DecodeInstruction(instrInfo)
		}
	}
	return ocsd.ErrDcdInterfaceUnused
}

// InvalidateMemAccCache invalidates the memory access cache for the given trace ID.
func (b *DecoderBase) InvalidateMemAccCache(traceID uint8) error {
	if !b.UsesMemAccess {
		return ocsd.ErrDcdInterfaceUnused
	}
	if b.MemAccess != nil {
		b.MemAccess.InvalidateMemAccCache(traceID)
	}
	return nil
}

// ProcBase holds the shared state for a packet processor.
// Concrete processors hold it as a named field and call its methods explicitly.
type ProcBase struct {
	Name             string
	Logger           ocsd.Logger
	ErrVerbosity     ocsd.ErrSeverity
	OpFlags          uint32
	SupportedOpFlags uint32

	PktOutI    any // ocsd.PacketProcessor[P] stored as any; processors access it via their own typed field
	PktRawMonI any // ocsd.PacketMonitor[P] stored as any; same

	Stats     ocsd.DecodeStats
	statsInit bool
}

// Init sets up the ProcBase.
func (b *ProcBase) Init(name string, logger ocsd.Logger) {
	b.Name = name
	b.Logger = logger
	b.ErrVerbosity = ocsd.ErrSevNone
	b.ResetStats()
}

// LogError logs an error if the logger is set and severity threshold is met.
func (b *ProcBase) LogError(sev ocsd.ErrSeverity, err error) {
	if err == nil {
		return
	}
	if b.Logger != nil && b.IsLoggingErrorLevel(sev) {
		b.Logger.LogError(sev, err)
	}
}

// LogMessage logs a message at the given severity level.
func (b *ProcBase) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	if filterLevel <= b.ErrVerbosity && b.Logger != nil {
		b.Logger.LogMessage(filterLevel, msg)
	}
}

// IsLoggingErrorLevel reports whether errors at the given severity should be logged.
func (b *ProcBase) IsLoggingErrorLevel(level ocsd.ErrSeverity) bool {
	return level <= b.ErrVerbosity
}

// ConfigureComponentOpMode applies opFlags masked to the supported set.
func (b *ProcBase) ConfigureComponentOpMode(opFlags uint32) error {
	b.OpFlags = opFlags & b.SupportedOpFlags
	return nil
}

// ComponentOpMode returns the current operational mode flags.
func (b *ProcBase) ComponentOpMode() uint32 { return b.OpFlags }

// SupportedOpModes returns the supported operational mode bitmask.
func (b *ProcBase) SupportedOpModes() uint32 { return b.SupportedOpFlags }

// ConfigureSupportedOpModes sets which op-mode flags this processor supports.
func (b *ProcBase) ConfigureSupportedOpModes(flags uint32) { b.SupportedOpFlags = flags }

// StatsBlock returns the decode statistics, or ErrNotInit if stats were never initialized.
func (b *ProcBase) StatsBlock() (*ocsd.DecodeStats, error) {
	if !b.statsInit {
		return &b.Stats, ocsd.ErrNotInit
	}
	return &b.Stats, nil
}

// HasRawMon reports whether a raw packet monitor has been attached.
// Processors call this to check the PktRawMonI field directly.
func (b *ProcBase) HasRawMon() bool { return b.PktRawMonI != nil }

// ResetStats zeroes all decode statistics fields.
func (b *ProcBase) ResetStats() {
	b.Stats.Version = ocsd.VerNum
	b.Stats.Revision = ocsd.StatsRevision
	b.Stats.ChannelTotal = 0
	b.Stats.ChannelUnsynced = 0
	b.Stats.BadHeaderErrs = 0
	b.Stats.BadSequenceErrs = 0
	b.Stats.Demux.FrameBytes = 0
	b.Stats.Demux.NoIDBytes = 0
	b.Stats.Demux.ValidIDBytes = 0
}

// StatsInit marks the statistics block as initialized.
func (b *ProcBase) StatsInit() { b.statsInit = true }

// StatsAddTotalCount adds to the total channel bytes counter.
func (b *ProcBase) StatsAddTotalCount(count uint64) { b.Stats.ChannelTotal += count }

// StatsAddUnsyncCount adds to the unsynced channel bytes counter.
func (b *ProcBase) StatsAddUnsyncCount(count uint64) { b.Stats.ChannelUnsynced += count }

// StatsAddBadSeqCount adds to the bad-sequence-error counter.
func (b *ProcBase) StatsAddBadSeqCount(count uint32) { b.Stats.BadSequenceErrs += count }

// StatsAddBadHdrCount adds to the bad-header-error counter.
func (b *ProcBase) StatsAddBadHdrCount(count uint32) { b.Stats.BadHeaderErrs += count }
