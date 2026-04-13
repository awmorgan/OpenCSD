package ocsd

import "iter"

// TraceIterator is the pull-based interface for generic trace elements.
type TraceIterator interface {
	Next() (*TraceElement, error)
	Elements() iter.Seq2[*TraceElement, error]
}
