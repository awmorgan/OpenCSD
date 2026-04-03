package ocsd

// TraceIterator is the pull-based interface for generic trace elements.
type TraceIterator interface {
	Next() (*TraceElement, error)
}
