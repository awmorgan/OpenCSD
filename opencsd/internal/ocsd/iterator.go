package ocsd

import (
	"errors"
	"io"
	"iter"
)

// TraceIterator is the pull-based interface for generic trace elements.
type TraceIterator interface {
	Next() (*TraceElement, error)
	Elements() iter.Seq2[*TraceElement, error]
}

func generateSeq[T any](next func() (T, error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		for {
			item, err := next()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					yield(zero, err)
				}
				return
			}
			if !yield(item, nil) {
				return
			}
		}
	}
}

// GenerateElements converts a pull-based Next() function into a standard Go 1.23 iterator.
func GenerateElements(next func() (*TraceElement, error)) iter.Seq2[*TraceElement, error] {
	return generateSeq(next)
}

// GeneratePackets converts a pull-based NextPacket() function into a standard Go 1.23 iterator.
func GeneratePackets[T any](next func() (T, error)) iter.Seq2[T, error] {
	return generateSeq(next)
}
