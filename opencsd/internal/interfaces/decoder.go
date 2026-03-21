package interfaces

import "opencsd/internal/ocsd"

// TrcTypedBase is the common typed base for decoder manager-created objects.
// It mirrors the role of C++ ITrcTypedBase while preserving Go type assertions
// at call sites.
type TrcTypedBase any

// DecoderMngr is the interface for a protocol trace decoder factory.
// It creates packet processors and decoders for a specific trace protocol.
type DecoderMngr interface {
	CreatePktProc(instID int, config any) TrcTypedBase
	CreatePktDecode(instID int, config any) TrcTypedBase
	CreateDecoder(instID int, config any) (TrcDataIn, TrcTypedBase, ocsd.Err)
	ProtocolType() ocsd.TraceProtocol
}

// TypedDecoderMngr is an optional Go-native constructor interface.
// DecodeTree prefers this when available so built-in managers can avoid the
// legacy any-returning factory path while preserving compatibility.
type TypedDecoderMngr interface {
	CreateTypedPktProc(instID int, config any) (TrcDataIn, TrcTypedBase, ocsd.Err)
	CreateTypedDecoder(instID int, config any) (TrcDataIn, TrcTypedBase, ocsd.Err)
}
