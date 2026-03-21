package interfaces

import "opencsd/internal/ocsd"

// TrcTypedBase is the common typed base for decoder manager-created objects.
// It mirrors the role of C++ ITrcTypedBase while preserving Go type assertions
// at call sites.
type TrcTypedBase any

// DecoderMngr identifies a registered decoder manager by protocol.
// Construction capabilities are exposed through optional interfaces.
type DecoderMngr interface {
	ProtocolType() ocsd.TraceProtocol
}

// LegacyDecoderMngr is the compatibility interface for the original any-based
// constructor API.
type LegacyDecoderMngr interface {
	CreatePktProc(instID int, config any) TrcTypedBase
	CreatePktDecode(instID int, config any) TrcTypedBase
	CreateDecoder(instID int, config any) (TrcDataIn, TrcTypedBase, ocsd.Err)
}

// TypedDecoderMngr is an optional Go-native constructor interface.
// DecodeTree prefers this when available so built-in managers can avoid the
// legacy any-returning factory path while preserving compatibility.
type TypedDecoderMngr interface {
	CreateTypedPktProc(instID int, config any) (TrcDataIn, TrcTypedBase, ocsd.Err)
	CreateTypedDecoder(instID int, config any) (TrcDataIn, TrcTypedBase, ocsd.Err)
}
