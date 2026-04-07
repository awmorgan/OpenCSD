package ocsd

import "fmt"

type MemAccessor func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// TrcDataProcessData is the explicit data-path method for trace data input.
type TrcDataProcessData interface {
	TraceData(index TrcIndex, dataBlock []byte) (uint32, error)
}

// TrcDataProcessControl carries explicit lifecycle operations for datapath components.
type TrcDataProcessControl interface {
	TraceDataEOT() error
	TraceDataFlush() error
	TraceDataReset(index TrcIndex) error
}

// TrcDataProcessorExplicit combines explicit data and lifecycle methods.
type TrcDataProcessorExplicit interface {
	TrcDataProcessData
	TrcDataProcessControl
}

// GenElemProcessor is the input interface for generic trace elements.
type GenElemProcessor interface {
	TraceElemIn(indexSOP TrcIndex, trcChanID uint8, elem *TraceElement) error
}

// PacketProcessData is the explicit data-path packet method.
type PacketProcessData[P any] interface {
	TracePacketData(indexSOP TrcIndex, pkt *P) error
}

// PacketProcessControl carries explicit lifecycle operations for packet consumers.
type PacketProcessControl interface {
	TracePacketEOT() error
	TracePacketFlush() error
	TracePacketReset(indexSOP TrcIndex) error
}

// PacketProcessorExplicit combines explicit packet data and lifecycle methods.
type PacketProcessorExplicit[P any] interface {
	PacketProcessData[P]
	PacketProcessControl
}

// PacketMonitor provides packet monitor functionality off the decode path.
type PacketMonitor interface {
	RawPacketDataMon(op DatapathOp, indexSOP TrcIndex, pkt fmt.Stringer, rawData []byte)
}

// RawFrameProcessor is the input interface for raw frame bytes.
type RawFrameProcessor interface {
	TraceRawFrameIn(op DatapathOp, index TrcIndex, frameElem RawframeElem, data []byte, traceID uint8) error
}
