package dcdtree

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type traceElemSetterOwner interface {
	SetTraceElemOut(ocsd.GenElemProcessor)
}

type instrDecodeSetterOwner interface {
	SetInstrDecode(common.InstrDecode)
}

type memAccSetterOwner interface {
	SetMemAccess(common.TargetMemAccess)
}

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                // Registered name of the decoder
	DataIn          ocsd.TrcDataProcessor // Interface for feeding trace data
	DecoderHandle   any                   // Pointer to the decoder processor (PktDecode)
	SetTraceElemOut func(ocsd.GenElemProcessor)
	SetInstrDecode  func(common.InstrDecode)
	SetMemAccess    func(common.TargetMemAccess)
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

	var setInstrDecode func(common.InstrDecode)
	if owner, ok := dcdHandle.(instrDecodeSetterOwner); ok {
		setInstrDecode = owner.SetInstrDecode
	}

	var setMemAccess func(common.TargetMemAccess)
	if owner, ok := dcdHandle.(memAccSetterOwner); ok {
		setMemAccess = owner.SetMemAccess
	}

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DataIn:          dataIn,
		DecoderHandle:   dcdHandle,
		SetTraceElemOut: setTraceElemOut,
		SetInstrDecode:  setInstrDecode,
		SetMemAccess:    setMemAccess,
		Protocol:        protocol,
		Created:         created,
	}
}
