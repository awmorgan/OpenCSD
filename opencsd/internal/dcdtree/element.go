package dcdtree

import (
	"opencsd/internal/ocsd"
)

// DecoderHandle is the typed decoder registration handle stored by the decode tree.
// Concrete values may be packet processors or packet decoders, depending on pipeline mode.
type DecoderHandle interface{}

// pipelineWiringOwner defines the explicit late-binding contract used by decode tree
// when dependencies must be wired after decoder construction.
type pipelineWiringOwner interface {
	SetTraceElemOut(ocsd.GenElemProcessor)
}

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                        // Registered name of the decoder
	DataIn          ocsd.TrcDataProcessorExplicit // Interface for feeding trace data
	DecoderHandle   DecoderHandle                 // Decoder registration handle
	PipelineWiring  pipelineWiringOwner           // Explicit late-bound dependency wiring owner
	Protocol        ocsd.TraceProtocol            // Protocol type
	Created         bool                          // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, dcdHandle DecoderHandle, wiring pipelineWiringOwner, dataIn ocsd.TrcDataProcessorExplicit, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DataIn:          dataIn,
		DecoderHandle:   dcdHandle,
		PipelineWiring:  wiring,
		Protocol:        protocol,
		Created:         created,
	}
}
