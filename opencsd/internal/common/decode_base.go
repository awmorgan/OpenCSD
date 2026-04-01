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

// OpModeManager provides access to the operational mode flags of a component.
type OpModeManager interface {
	ComponentOpMode() uint32
	SupportedOpModes() uint32
	SetComponentOpMode(opFlags uint32) error
	ConfigureSupportedOpModes(flags uint32)
}

// TraceElementOutputter provides methods to send trace elements downstream.
type TraceElementOutputter interface {
	OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp
	OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp
}

// BaseLogger is an embeddable component that provides logging functionality.
// Embed this in a struct to add LogError, LogMessage, and IsLoggingErrorLevel methods.
type BaseLogger struct {
	Logger       ocsd.Logger
	ErrVerbosity ocsd.ErrSeverity
}

// LogError logs an error if the logger is set and the severity threshold is met.
func (l *BaseLogger) LogError(sev ocsd.ErrSeverity, err error) {
	if err == nil {
		return
	}
	if l.Logger != nil && l.IsLoggingErrorLevel(sev) {
		l.Logger.LogError(sev, err)
	}
}

// LogMessage logs a message at the given severity level.
func (l *BaseLogger) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	if filterLevel <= l.ErrVerbosity && l.Logger != nil {
		l.Logger.LogMessage(filterLevel, msg)
	}
}

// IsLoggingErrorLevel reports whether errors at the given severity should be logged.
func (l *BaseLogger) IsLoggingErrorLevel(level ocsd.ErrSeverity) bool {
	return level <= l.ErrVerbosity
}

// OpMode is an embeddable component that manages operational mode flags.
// Embed this in a struct to add SetComponentOpMode, ComponentOpMode,
// SupportedOpModes, and ConfigureSupportedOpModes methods.
type OpMode struct {
	OpFlags          uint32
	SupportedOpFlags uint32
}

// SetComponentOpMode applies opFlags masked to the supported set.
func (m *OpMode) SetComponentOpMode(opFlags uint32) error {
	m.OpFlags = opFlags & m.SupportedOpFlags
	return nil
}

// ComponentOpMode returns the current operational mode flags.
func (m *OpMode) ComponentOpMode() uint32 { return m.OpFlags }

// SupportedOpModes returns the supported operational mode bitmask.
func (m *OpMode) SupportedOpModes() uint32 { return m.SupportedOpFlags }

// ConfigureSupportedOpModes sets which op-mode flags this component supports.
func (m *OpMode) ConfigureSupportedOpModes(flags uint32) { m.SupportedOpFlags = flags }

// DecoderBase holds the shared state for a packet decoder.
// It composes OpMode for operational flag management.
// Concrete decoders embed this struct and call its methods via promotion.
type DecoderBase struct {
	Name string
	OpMode

	TraceElemOut ocsd.GenElemProcessor
	MemAccess    TargetMemAccess
	InstrDecode  InstrDecode

	IndexCurrPkt  ocsd.TrcIndex
	ConfigInitOK  bool
	UsesMemAccess bool
	UsesIDecode   bool
}

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
// It composes BaseLogger for logging and OpMode for operational flag management.
// Concrete processors embed this struct and call its methods via promotion.
type ProcBase[P any] struct {
	Name string
	BaseLogger
	OpMode

	PktOutI    ocsd.PacketProcessor[P]
	PktRawMonI ocsd.PacketMonitor[P]

	Stats     ocsd.DecodeStats
	statsInit bool
}

// StatsBlock returns the decode statistics, or ErrNotInit if stats were never initialized.
func (b *ProcBase[P]) StatsBlock() (*ocsd.DecodeStats, error) {
	if !b.statsInit {
		return &b.Stats, ocsd.ErrNotInit
	}
	return &b.Stats, nil
}

// HasRawMon reports whether a raw packet monitor has been attached.
// Processors call this to check the PktRawMonI field directly.
func (b *ProcBase[P]) HasRawMon() bool { return b.PktRawMonI != nil }

// ResetStats zeroes all decode statistics fields.
func (b *ProcBase[P]) ResetStats() {
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
func (b *ProcBase[P]) StatsInit() { b.statsInit = true }

// StatsAddTotalCount adds to the total channel bytes counter.
func (b *ProcBase[P]) StatsAddTotalCount(count uint64) { b.Stats.ChannelTotal += count }

// StatsAddUnsyncCount adds to the unsynced channel bytes counter.
func (b *ProcBase[P]) StatsAddUnsyncCount(count uint64) { b.Stats.ChannelUnsynced += count }

// StatsAddBadSeqCount adds to the bad-sequence-error counter.
func (b *ProcBase[P]) StatsAddBadSeqCount(count uint32) { b.Stats.BadSequenceErrs += count }

// StatsAddBadHdrCount adds to the bad-header-error counter.
func (b *ProcBase[P]) StatsAddBadHdrCount(count uint32) { b.Stats.BadHeaderErrs += count }
