package interfaces

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// TrcDataIn represents ITrcDataIn.
// It is the generic interface for supplying raw trace data to a component
// in the decode datapath.
type TrcDataIn interface {
	// TraceDataIn processes trace data.
	// We use an idiomatic Go slice for the data block, returning number of bytes processed and resp code.
	TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, ocsd.DatapathResp)
}

// TrcGenElemIn represents ITrcGenElemIn.
// Interface for the input of generic trace elements.
type TrcGenElemIn interface {
	TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *common.TraceElement) ocsd.DatapathResp
}

// PktDataIn represents IPktDataIn<P>.
// Provide input for discrete protocol packets.
type PktDataIn[P any] interface {
	PacketDataIn(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *P) ocsd.DatapathResp
}

// PktRawDataMon represents IPktRawDataMon<P>.
// Monitor functionality not on decode path.
type PktRawDataMon[P any] interface {
	RawPacketDataMon(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *P, rawData []byte)
}
