package interfaces

import "opencsd/internal/ocsd"

// DecoderMngr identifies a registered decoder manager by protocol.
// Construction capabilities are exposed through optional interfaces.
type DecoderMngr interface {
	ProtocolType() ocsd.TraceProtocol
}

// TypedDecoderMngr is an optional Go-native constructor interface.
// DecodeTree requires this constructor surface for registered managers.
type TypedDecoderMngr interface {
	CreateTypedPktProc(instID int, config any) (TrcDataIn, any, ocsd.Err)
	CreateTypedDecoder(instID int, config any) (TrcDataIn, any, ocsd.Err)
}
