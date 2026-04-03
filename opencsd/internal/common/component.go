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

// FlagApplier applies user-requested decoder/processor mode flags.
type FlagApplier interface {
	ApplyFlags(flags uint32) error
}

// TraceElementOutputter provides methods to send trace elements downstream.
type TraceElementOutputter interface {
	OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error
	OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error
}
