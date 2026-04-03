package dcdtree

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// wireTraceElemFn is the function type used to wire a trace element sink into a decoder after
// construction. Callers may pass a decoder method value (dec.SetTraceElemOut) or a plain closure.
type wireTraceElemFn func(ocsd.GenElemProcessor)

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                        // Registered name of the decoder
	DataIn          ocsd.TrcDataProcessorExplicit // Interface for feeding trace data
	Iterator        ocsd.TraceIterator            // Pull-based iterator output path
	PushAdapter     *common.PushToPullAdapter     // Legacy push->pull bridge when iterator is not available
	FlagApplier     common.FlagApplier            // Optional flag applier for decoder or processor
	PipelineWiring  wireTraceElemFn               // Explicit late-bound dependency wiring owner
	Protocol        ocsd.TraceProtocol            // Protocol type
	Created         bool                          // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, flagApplier common.FlagApplier, wiring wireTraceElemFn, dataIn ocsd.TrcDataProcessorExplicit, iterator ocsd.TraceIterator, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DataIn:          dataIn,
		Iterator:        iterator,
		PushAdapter:     nil,
		FlagApplier:     flagApplier,
		PipelineWiring:  wiring,
		Protocol:        protocol,
		Created:         created,
	}
}
