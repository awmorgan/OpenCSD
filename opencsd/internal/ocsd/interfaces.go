package ocsd

import "fmt"

type MemAccessor func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// Replace the 6 Trc/Packet interfaces with these two:
type TraceProcessor interface {
	TraceData(index TrcIndex, dataBlock []byte) (uint32, error)
	TraceDataEOT() error
	TraceDataFlush() error
	TraceDataReset(index TrcIndex) error
}

type PacketProcessor[P any] interface {
	TracePacketData(indexSOP TrcIndex, pkt *P) error
	TracePacketEOT() error
	TracePacketFlush() error
	TracePacketReset(indexSOP TrcIndex) error
}

// PacketMonitor provides packet monitor functionality off the decode path.
type PacketMonitor interface {
	RawPacketDataMon(op DatapathOp, indexSOP TrcIndex, pkt fmt.Stringer, rawData []byte)
}

// GenElemProcessor is the input interface for generic trace elements.
type GenElemProcessor interface {
	TraceElemIn(indexSOP TrcIndex, trcChanID uint8, elem *TraceElement) error
}

// RawFrameProcessor is the input interface for raw frame bytes.
type RawFrameProcessor interface {
	TraceRawFrameIn(op DatapathOp, index TrcIndex, frameElem RawframeElem, data []byte, traceID uint8) error
}
