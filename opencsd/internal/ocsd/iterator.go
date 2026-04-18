package ocsd

import "iter"

// TraceIterator is the pull-based interface for generic trace elements.
type TraceIterator interface {
	Next() (*TraceElement, error)
	Elements() iter.Seq2[*TraceElement, error]
}

// ElementSinkFn is a callback used to push elements out of a decoder instantly.
// Returning false signals the decoder to stop processing (e.g., iterator break).
type ElementSinkFn func(idx TrcIndex, traceID uint8, elem *TraceElement) bool

// TraceElementSink is an interface for decoders that support direct,
// zero-allocation element emission.
type TraceElementSink interface {
	SetElementSink(fn ElementSinkFn)
}
