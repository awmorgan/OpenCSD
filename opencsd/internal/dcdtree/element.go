package dcdtree

import (
	"opencsd/internal/common"
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

type traceElemAttachOwner interface {
	TraceElemOutAttachPt() *common.AttachPt[interfaces.TrcGenElemIn]
}

type instrDecodeAttachOwner interface {
	InstrDecodeAttachPt() *common.AttachPt[common.InstrDecode]
}

type memAccAttachOwner interface {
	MemAccAttachPt() *common.AttachPt[common.TargetMemAccess]
}

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                 // Registered name of the decoder
	DecoderMngr     interfaces.DecoderMngr // Factory interface that created it
	DataIn          interfaces.TrcDataIn   // Interface for feeding trace data
	DecoderHandle   any                    // Pointer to the decoder processor (PktDecode)
	TraceElemAttach *common.AttachPt[interfaces.TrcGenElemIn]
	InstrDecAttach  *common.AttachPt[common.InstrDecode]
	MemAccAttach    *common.AttachPt[common.TargetMemAccess]
	Protocol        ocsd.TraceProtocol     // Protocol type
	Created         bool                   // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, dcdMngr interfaces.DecoderMngr, dcdHandle any, dataIn interfaces.TrcDataIn, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown
	if dcdMngr != nil {
		protocol = dcdMngr.ProtocolType()
	}

	var traceElemAttach *common.AttachPt[interfaces.TrcGenElemIn]
	if owner, ok := dcdHandle.(traceElemAttachOwner); ok {
		traceElemAttach = owner.TraceElemOutAttachPt()
	}

	var instrDecAttach *common.AttachPt[common.InstrDecode]
	if owner, ok := dcdHandle.(instrDecodeAttachOwner); ok {
		instrDecAttach = owner.InstrDecodeAttachPt()
	}

	var memAccAttach *common.AttachPt[common.TargetMemAccess]
	if owner, ok := dcdHandle.(memAccAttachOwner); ok {
		memAccAttach = owner.MemAccAttachPt()
	}

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DecoderMngr:     dcdMngr,
		DataIn:          dataIn,
		DecoderHandle:   dcdHandle,
		TraceElemAttach: traceElemAttach,
		InstrDecAttach:  instrDecAttach,
		MemAccAttach:    memAccAttach,
		Protocol:        protocol,
		Created:         created,
	}
}
