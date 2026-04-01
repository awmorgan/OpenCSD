package common

import "opencsd/internal/ocsd"

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
	OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error
	OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error
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
