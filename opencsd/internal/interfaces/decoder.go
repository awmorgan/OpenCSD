package interfaces

import "opencsd/internal/ocsd"

// DecoderMngr identifies a registered decoder manager by protocol.
// Construction capabilities are exposed through optional interfaces.
type DecoderMngr interface {
	ProtocolType() ocsd.TraceProtocol
}

// LegacyPktProcMngr is the compatibility interface for the original any-based
// packet-processor factory API.
type LegacyPktProcMngr interface {
	CreatePktProc(instID int, config any) any
	}

// LegacyDecoderFactory is the compatibility interface for the original any-based
// full-decoder factory API.
type LegacyDecoderFactory interface {
	CreateDecoder(instID int, config any) (TrcDataIn, any, ocsd.Err)
}

// TypedDecoderMngr is an optional Go-native constructor interface.
// DecodeTree prefers this when available so built-in managers can avoid the
// legacy any-returning factory path while preserving compatibility.
type TypedDecoderMngr interface {
	CreateTypedPktProc(instID int, config any) (TrcDataIn, any, ocsd.Err)
	CreateTypedDecoder(instID int, config any) (TrcDataIn, any, ocsd.Err)
}
