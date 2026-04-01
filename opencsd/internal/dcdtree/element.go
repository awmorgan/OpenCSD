package dcdtree

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// pipelineWiringOwner defines the explicit late-binding contract used by decode tree
// when dependencies must be wired after decoder construction.
type pipelineWiringOwner interface {
	SetTraceElemOut(ocsd.GenElemProcessor)
	SetMemAccess(common.TargetMemAccess)
	SetInstrDecode(common.InstrDecode)
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
