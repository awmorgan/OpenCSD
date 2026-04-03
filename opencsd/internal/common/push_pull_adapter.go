package common

import (
	"io"
	"sync"

	"opencsd/internal/ocsd"
)

// PushToPullAdapter bridges the push-based generic element sink to a pull-based iterator.
type PushToPullAdapter struct {
	mu    sync.Mutex
	queue []*ocsd.TraceElement
}

// NewPushToPullAdapter creates an empty push-to-pull bridge.
func NewPushToPullAdapter() *PushToPullAdapter {
	return &PushToPullAdapter{
		queue: make([]*ocsd.TraceElement, 0, 16),
	}
}

// TraceElemIn appends a copy of the incoming element to the internal queue.
func (a *PushToPullAdapter) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	_ = indexSOP
	_ = trcChanID

	a.mu.Lock()
	defer a.mu.Unlock()

	a.queue = append(a.queue, cloneTraceElement(elem))
	return nil
}

// Next dequeues the next available trace element, or returns io.EOF if the queue is empty.
func (a *PushToPullAdapter) Next() (*ocsd.TraceElement, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.queue) == 0 {
		return nil, io.EOF
	}

	elem := a.queue[0]
	a.queue[0] = nil
	a.queue = a.queue[1:]
	return elem, nil
}

func cloneTraceElement(elem *ocsd.TraceElement) *ocsd.TraceElement {
	if elem == nil {
		return nil
	}

	clone := *elem
	if elem.PtrExtendedData != nil {
		clone.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return &clone
}

var _ ocsd.GenElemProcessor = (*PushToPullAdapter)(nil)
var _ ocsd.TraceIterator = (*PushToPullAdapter)(nil)
