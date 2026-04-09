package ocsd

import "fmt"

type MemAccessor func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// Replace the 6 Trc/Packet interfaces with these two:
type TraceDecoder interface {
	Write(index TrcIndex, dataBlock []byte) (uint32, error)
	Close() error
	Flush() error
	Reset(index TrcIndex) error
}

type PacketProcessor[P any] interface {
	Write(indexSOP TrcIndex, pkt *P) error
	Close() error
	Flush() error
	Reset(indexSOP TrcIndex) error
}

// PacketMonitor provides packet monitor functionality off the decode path.
type PacketMonitor interface {
	MonitorRawData(indexSOP TrcIndex, pkt fmt.Stringer, rawData []byte)
	MonitorEOT()
	MonitorReset(indexSOP TrcIndex)
}

// GenElemProcessor is the input interface for generic trace elements.
type GenElemProcessor interface {
	TraceElemIn(indexSOP TrcIndex, trcChanID uint8, elem *TraceElement) error
}

// RawFrameProcessor is the input interface for raw frame bytes.
type RawFrameProcessor interface {
	WriteRawFrame(index TrcIndex, frameElem RawframeElem, data []byte, traceID uint8) error
	FlushRawFrames() error
	ResetRawFrames() error
	CloseRawFrames() error
}
