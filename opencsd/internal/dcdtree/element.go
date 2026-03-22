package dcdtree

import (
	"opencsd/internal/common"

	"opencsd/internal/ocsd"
)

type traceElemSetterOwner interface {
	SetTraceElemOut(ocsd.TrcGenElemIn)
}

type instrDecodeSetterOwner interface {
	SetInstrDecode(common.InstrDecode)
}

type memAccSetterOwner interface {
	SetMemAccess(common.TargetMemAccess)
}

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string              // Registered name of the decoder
	DecoderManager  ocsd.DecoderManager // Factory interface that created it
	DataIn          ocsd.TrcDataIn      // Interface for feeding trace data
	DecoderHandle   any                 // Pointer to the decoder processor (PktDecode)
	SetTraceElemOut func(ocsd.TrcGenElemIn)
	SetInstrDecode  func(common.InstrDecode)
	SetMemAccess    func(common.TargetMemAccess)
	Protocol        ocsd.TraceProtocol // Protocol type
	Created         bool               // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, decoderManager ocsd.DecoderManager, dcdHandle any, dataIn ocsd.TrcDataIn, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown
	if decoderManager != nil {
		protocol = decoderManager.Protocol()
	}

	var setTraceElemOut func(ocsd.TrcGenElemIn)
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
		DecoderManager:  decoderManager,
		DataIn:          dataIn,
		DecoderHandle:   dcdHandle,
		SetTraceElemOut: setTraceElemOut,
		SetInstrDecode:  setInstrDecode,
		SetMemAccess:    setMemAccess,
		Protocol:        protocol,
		Created:         created,
	}
}
