package interfaces

import "opencsd/internal/ocsd"

// DecoderMngr identifies a registered decoder manager by protocol.
// It provides typed construction of packet processors and full decoders.
type DecoderMngr interface {
	CreateTypedPktProc(instID int, config any) (TrcDataIn, any, ocsd.Err)
	CreateTypedDecoder(instID int, config any) (TrcDataIn, any, ocsd.Err)
	ProtocolType() ocsd.TraceProtocol
}
