package dcdtree

import "opencsd/internal/ocsd"

// wireTraceElemFn is the function type used to wire a trace element sink into a decoder after
// construction. Callers may pass a decoder method value (dec.SetTraceElemOut) or a plain closure.
type wireTraceElemFn func(ocsd.GenElemProcessor)

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                        // Registered name of the decoder
	DataIn          ocsd.TrcDataProcessorExplicit // Interface for feeding trace data
	Manager         OpModeComponent               // Operational mode manager for decoder
	PipelineWiring  wireTraceElemFn               // Explicit late-bound dependency wiring owner
	Protocol        ocsd.TraceProtocol            // Protocol type
	Created         bool                          // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, modeManager OpModeComponent, wiring wireTraceElemFn, dataIn ocsd.TrcDataProcessorExplicit, created bool) *DecodeTreeElement {
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
