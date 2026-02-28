package interfaces

import "opencsd/internal/ocsd"

// DecoderMngr is the interface for a protocol trace decoder factory.
// It creates packet processors and decoders for a specific trace protocol.
type DecoderMngr interface {
	CreatePktProc(instID int, config any) any
	CreatePktDecode(instID int, config any) any
	CreateDecoder(instID int, config any) (TrcDataIn, any, ocsd.Err)
	ProtocolType() ocsd.TraceProtocol
}
