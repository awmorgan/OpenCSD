package ocsd

// FnMemAccCB is the callback function definition for callback function memory accessor type.
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
type FnMemAccCB func(address VAddr, memSpace MemSpaceAcc, reqBytes uint32, buffer []byte) uint32

// FnMemAccIDCB is the callback function definition for callback function memory accessor type.
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
type FnMemAccIDCB func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// TrcDataIn is the generic interface for supplying raw trace data
// to a component in the decode datapath.
type TrcDataIn interface {
	// TraceDataIn processes trace data.
	// We use an idiomatic Go slice for the data block, returning
	// number of bytes processed, datapath flow-control response, and a root-cause error.
	TraceDataIn(op DatapathOp, index TrcIndex, dataBlock []byte) (uint32, DatapathResp, error)
}

// TrcGenElemIn is the input interface for generic trace elements.
type TrcGenElemIn interface {
	TraceElemIn(indexSOP TrcIndex, trcChanID uint8, elem *TraceElement) DatapathResp
}

// PktDataIn provides input for discrete protocol packets.
type PktDataIn[P any] interface {
	PacketDataIn(op DatapathOp, indexSOP TrcIndex, pkt *P) DatapathResp
}

// PktRawDataMon provides packet monitor functionality off the decode path.
type PktRawDataMon[P any] interface {
	RawPacketDataMon(op DatapathOp, indexSOP TrcIndex, pkt *P, rawData []byte)
}

// TrcRawFrameIn is the input interface for raw frame bytes.
type TrcRawFrameIn interface {
	TraceRawFrameIn(op DatapathOp, index TrcIndex, frameElem RawframeElem, data []byte, traceID uint8) DatapathResp
}

// DecoderManager identifies a registered decoder manager by protocol.
// It provides construction of packet processors and full decoders.
type DecoderManager interface {
	CreatePacketProcessor(instID int, config any) (TrcDataIn, any, error)
	CreateDecoder(instID int, config any) (TrcDataIn, any, error)
	Protocol() TraceProtocol
}
