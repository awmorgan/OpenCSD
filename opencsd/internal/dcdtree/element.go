package dcdtree

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// DecodeTreeElement represents a registered decoder instance within the trace decode tree.
type DecodeTreeElement struct {
	DecoderTypeName string             // Registered name of the decoder
	DataIn          ocsd.TraceDecoder  // Interface for feeding trace data
	Iterator        ocsd.TraceIterator // Pull-based iterator output path
	FlagApplier     common.FlagApplier // Optional flag applier for decoder or processor
	Protocol        ocsd.TraceProtocol // Protocol type
	Created         bool               // True if decode tree created this element
}

// NewDecodeTreeElement creates a new DecodeTreeElement record.
func NewDecodeTreeElement(name string, flagApplier common.FlagApplier, dataIn ocsd.TraceDecoder, iterator ocsd.TraceIterator, created bool) *DecodeTreeElement {
	protocol := ocsd.ProtocolUnknown

	return &DecodeTreeElement{
		DecoderTypeName: name,
		DataIn:          dataIn,
		Iterator:        iterator,
		FlagApplier:     flagApplier,
		Protocol:        protocol,
		Created:         created,
	}
}
