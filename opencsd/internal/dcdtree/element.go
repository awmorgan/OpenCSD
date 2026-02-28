package dcdtree

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string                 // Registered name of the decoder
	DecoderMngr     interfaces.DecoderMngr // Factory interface that created it
	DataIn          interfaces.TrcDataIn   // Interface for feeding trace data
	DecoderHandle   any                    // Pointer to the decoder processor (PktDecode)
	Protocol        ocsd.TraceProtocol     // Protocol type
	Created         bool                   // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, dcdMngr interfaces.DecoderMngr, dcdHandle any, dataIn interfaces.TrcDataIn, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown
	if dcdMngr != nil {
		protocol = dcdMngr.ProtocolType()
	}

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DecoderMngr:     dcdMngr,
		DataIn:          dataIn,
		DecoderHandle:   dcdHandle,
		Protocol:        protocol,
		Created:         created,
	}
}
