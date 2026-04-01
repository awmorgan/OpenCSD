package dcdtree

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// traceElemWiringOwner defines the explicit late-binding contract for trace element output wiring.
// Decoder types that support late sink binding should implement this interface directly.
type traceElemWiringOwner interface {
	SetTraceElemOut(ocsd.GenElemProcessor)
}

// memAccessWiringOwner defines the explicit late-binding contract for memory access wiring.
// Decoder types that support late memory interface binding should implement this interface directly.
type memAccessWiringOwner interface {
	SetMemAccess(common.TargetMemAccess)
}

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                // Registered name of the decoder
	DataIn          ocsd.TrcDataProcessor // Interface for feeding trace data
	DecoderHandle   any                   // Pointer to the decoder processor (PktDecode)
	Protocol        ocsd.TraceProtocol // Protocol type
	Created         bool               // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, dcdHandle any, dataIn ocsd.TrcDataProcessor, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DataIn:          dataIn,
		DecoderHandle:   dcdHandle,
		Protocol:        protocol,
		Created:         created,
	}
}
