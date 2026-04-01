package dcdtree

import (
	"opencsd/internal/ocsd"
)

type traceElemSetterOwner interface {
	SetTraceElemOut(ocsd.GenElemProcessor)
}

// traceElemWiringOwner defines the explicit late-binding contract for trace element output wiring.
// Decoder types that support late sink binding should implement this interface directly.
type traceElemWiringOwner interface {
	SetTraceElemOut(ocsd.GenElemProcessor)
}

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                // Registered name of the decoder
	DataIn          ocsd.TrcDataProcessor // Interface for feeding trace data
	DecoderHandle   any                   // Pointer to the decoder processor (PktDecode)
	SetTraceElemOut func(ocsd.GenElemProcessor)
	Protocol        ocsd.TraceProtocol // Protocol type
	Created         bool               // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, dcdHandle any, dataIn ocsd.TrcDataProcessor, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown

	var setTraceElemOut func(ocsd.GenElemProcessor)
	if owner, ok := dcdHandle.(traceElemSetterOwner); ok {
		setTraceElemOut = owner.SetTraceElemOut
	}

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DataIn:          dataIn,
		DecoderHandle:   dcdHandle,
		SetTraceElemOut: setTraceElemOut,
		Protocol:        protocol,
		Created:         created,
	}
}
