package ocsd

// MemAccessor is the callback function definition for callback function memory accessor type.
//
// When using callback memory accessor, the decoder will call this function to obtain the
// memory at the address for the current opcodes. The memory space will represent the current
// exception level and security context of the traced code.
//
// Return the number of bytes read, which can be less than the amount requested if this would take the
// access address outside the range of addresses defined when this callback was registered with the decoder.
//
// Return 0 bytes if start address out of covered range, or memory space is not one of those defined as supported
// when the callback was registered.
type MemAccessor func(address VAddr, memSpace MemSpaceAcc, reqBytes uint32, buffer []byte) uint32

// MemAccessorWithID is the callback function definition for callback function memory accessor type.
//
// When using callback memory accessor, the decoder will call this function to obtain the
// memory at the address for the current opcodes. The memory space will represent the current
// exception level and security context of the traced code.
//
// Return the number of bytes read, which can be less than the amount requested if this would take the
// access address outside the range of addresses defined when this callback was registered with the decoder.
//
// Return 0 bytes if start address out of covered range, or memory space is not one of those defined as supported
// when the callback was registered.
type MemAccessorWithID func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// TrcDataProcessor is the generic interface for supplying raw trace data
// to a component in the decode datapath.
type TrcDataProcessor interface {
	// TraceDataIn processes trace data.
	// We use an idiomatic Go slice for the data block, returning
	// number of bytes processed, datapath flow-control response, and a root-cause error.
	TraceDataIn(op DatapathOp, index TrcIndex, dataBlock []byte) (uint32, DatapathResp, error)
}

// GenElemProcessor is the input interface for generic trace elements.
type GenElemProcessor interface {
	TraceElemIn(indexSOP TrcIndex, trcChanID uint8, elem *TraceElement) error
}

// PacketProcessor provides input for discrete protocol packets.
type PacketProcessor[P any] interface {
	PacketDataIn(op DatapathOp, indexSOP TrcIndex, pkt *P) error
}

// PacketMonitor provides packet monitor functionality off the decode path.
type PacketMonitor[P any] interface {
	RawPacketDataMon(op DatapathOp, indexSOP TrcIndex, pkt *P, rawData []byte)
}

// RawFrameProcessor is the input interface for raw frame bytes.
type RawFrameProcessor interface {
	TraceRawFrameIn(op DatapathOp, index TrcIndex, frameElem RawframeElem, data []byte, traceID uint8) error
}
