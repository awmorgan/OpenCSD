package common

import (
	"io"
	"sync"

	"opencsd/internal/ocsd"
)

// PushToPullAdapter bridges the push-based generic element sink to a pull-based iterator.
type PushToPullAdapter struct {
	mu        sync.Mutex
	cond      *sync.Cond
	current   *ocsd.TraceElement
	delivered bool
	closed    bool
	closeErr  error
}

// NewPushToPullAdapter creates an empty push-to-pull bridge.
func NewPushToPullAdapter() *PushToPullAdapter {
	adapter := &PushToPullAdapter{}
	adapter.cond = sync.NewCond(&adapter.mu)
	return adapter
}

// TraceElemIn hands a copy of the incoming element to the iterator consumer.
func (a *PushToPullAdapter) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for a.current != nil && !a.closed {
		a.cond.Wait()
	}
	if a.closed {
		return a.streamErr()
	}

	a.current = cloneTraceElement(indexSOP, trcChanID, elem)
	a.delivered = false
	a.cond.Signal()

	for a.current != nil && !a.closed {
		a.cond.Wait()
	}
	if a.closed {
		return a.streamErr()
	}
	return nil
}

// Next returns the next available trace element, blocking until one is available or the stream closes.
func (a *PushToPullAdapter) Next() (*ocsd.TraceElement, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for a.current != nil && a.delivered && !a.closed {
		a.cond.Wait()
	}

	for a.current == nil && !a.closed {
		a.cond.Wait()
	}

	if a.current == nil {
		return nil, a.streamErr()
	}

	a.delivered = true
	return a.current, nil
}

// TryNext returns the next available trace element without blocking.
// It returns io.EOF when no element is currently queued.
func (a *PushToPullAdapter) TryNext() (*ocsd.TraceElement, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.current == nil {
		if a.closed {
			return nil, a.streamErr()
		}
		return nil, io.EOF
	}
	if a.delivered {
		return nil, io.EOF
	}

	a.delivered = true
	return a.current, nil
}

// Ack marks the current delivered element as fully processed so the producer can continue.
func (a *PushToPullAdapter) Ack() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.current == nil || !a.delivered {
		return
	}

	a.current = nil
	a.delivered = false
	a.cond.Signal()
}

// Close marks the stream complete.
func (a *PushToPullAdapter) Close() {
	a.CloseWithError(nil)
}

// CloseWithError marks the stream complete and causes Next to return err once in-flight work completes.
func (a *PushToPullAdapter) CloseWithError(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return
	}
	a.closed = true
	a.closeErr = err
	a.cond.Broadcast()
}

func (a *PushToPullAdapter) streamErr() error {
	if a.closeErr != nil {
		return a.closeErr
	}
	return io.EOF
}

func cloneTraceElement(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) *ocsd.TraceElement {
	if elem == nil {
		return nil
	}

	clone := *elem
	clone.Index = indexSOP
	clone.TraceID = trcChanID
	if elem.PtrExtendedData != nil {
		clone.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return &clone
}

var _ ocsd.GenElemProcessor = (*PushToPullAdapter)(nil)
var _ ocsd.TraceIterator = (*PushToPullAdapter)(nil)
