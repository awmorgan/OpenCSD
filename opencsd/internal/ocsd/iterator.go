package ocsd

import "iter"

// TraceIterator is the pull-based interface for generic trace elements.
type TraceIterator interface {
	Next() (*TraceElement, error)
	Elements() iter.Seq2[*TraceElement, error]
}

// CallbackSink is implemented by decoders that can push elements to a callback sink.
type CallbackSink interface {
	SetOutCallback(cb func(idx TrcIndex, traceID uint8, elem *TraceElement) bool)
}
