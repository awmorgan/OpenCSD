package main

import (
	"io"
	"sync"
)

type synchronizedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *synchronizedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

type countingReader struct {
	r io.Reader
	n uint32
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += uint32(n)
	return n, err
}

func (r *countingReader) Count() uint32 {
	return r.n
}
