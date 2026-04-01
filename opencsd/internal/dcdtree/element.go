package dcdtree

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// pipelineWiringOwner defines the explicit late-binding contract used by decode tree
// when dependencies must be wired after decoder construction.
type pipelineWiringOwner interface {
	SetTraceElemOut(ocsd.GenElemProcessor)
}

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                        // Registered name of the decoder
	DataIn          ocsd.TrcDataProcessorExplicit // Interface for feeding trace data
	Manager         common.OpModeManager          // Operational mode manager for decoder
	PipelineWiring  pipelineWiringOwner           // Explicit late-bound dependency wiring owner
	Protocol        ocsd.TraceProtocol            // Protocol type
	Created         bool                          // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, modeManager common.OpModeManager, wiring pipelineWiringOwner, dataIn ocsd.TrcDataProcessorExplicit, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DataIn:          dataIn,
		Manager:         modeManager,
		PipelineWiring:  wiring,
		Protocol:        protocol,
		Created:         created,
	}
}
