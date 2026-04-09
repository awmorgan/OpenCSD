package ete

import (
	"fmt"
	"io"
	"opencsd/internal/common"
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
	"sync/atomic"
)

type traceElemEvent struct {
	seq     uint64
	index   ocsd.TrcIndex
	traceID uint8
	elem    ocsd.TraceElement
}

var queuedTraceElemSeq atomic.Uint64

type SequencedTraceIterator interface {
	NextSequenced() (uint64, *ocsd.TraceElement, error)
}

func (d *PktDecode) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	if d == nil || elem == nil {
		return nil
	}
	if d.traceElemOut != nil {
		if elem.ElemType != ocsd.GenElemEOTrace && indexSOP != 0 {
			d.lastElemIndex = indexSOP
			d.sawActivity = true
		}
		return d.traceElemOut.TraceElemIn(indexSOP, trcChanID, elem)
	}
	queueIndex := indexSOP
	if queueIndex == 0 && elem.ElemType == ocsd.GenElemEOTrace {
		if !d.sawActivity && d.lastPacketIndex == 0 && d.lastElemIndex == 0 {
			return nil
		}
		switch {
		case d.lastElemIndex != 0:
			queueIndex = d.lastElemIndex + 1
		case d.lastPacketIndex != 0:
			queueIndex = d.lastPacketIndex
		}
	} else if queueIndex != 0 {
		d.lastElemIndex = queueIndex
		d.sawActivity = true
	}
	queued := cloneTraceElement(elem)
	queued.TraceID = trcChanID

	seq := queuedTraceElemSeq.Add(1)
	d.pendingElements = append(d.pendingElements, traceElemEvent{
		seq:     seq,
		index:   queueIndex,
		traceID: queued.TraceID,
		elem:    queued,
	})

	return nil
}

type PktDecode struct {
	inner           *etmv4.PktDecode
	traceElemOut    ocsd.GenElemProcessor
	pendingElements []traceElemEvent
	lastPacketIndex ocsd.TrcIndex
	lastElemIndex   ocsd.TrcIndex
	sawActivity     bool
}

func NewPktDecode(cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	inner, err := etmv4.NewPktDecode(cfg.ToETMv4Config())
	if err != nil {
		return nil, err
	}
	decoder := &PktDecode{inner: inner}
	inner.SetTraceElemOut(decoder)
	return decoder, nil
}

// NewConfiguredPktDecodeWithDeps creates an ETE decoder and injects dependencies.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktDecode, error) {
	_ = instID
	decoder, err := NewPktDecode(cfg)
	if err != nil {
		return nil, err
	}
	decoder.inner.MemAccess = mem
	decoder.inner.InstrDecode = instr
	return decoder, nil
}

// NewConfiguredPipeline creates and wires a typed ETE processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*etmv4.Processor, *PktDecode, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}

	proc := NewProcessor(cfg)
	decoder, err := NewPktDecode(cfg)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(decoder)
	return proc, decoder, nil
}

// NewConfiguredPipelineWithDeps creates and wires an ETE processor/decoder pair with dependencies.
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*etmv4.Processor, *PktDecode, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}

	proc := NewProcessor(cfg)

	decoder, err := NewConfiguredPktDecodeWithDeps(instID, cfg, mem, instr)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(decoder)
	return proc, decoder, nil
}

func (d *PktDecode) ApplyFlags(flags uint32) error {
	if d == nil || d.inner == nil {
		return ocsd.ErrNotInit
	}
	return d.inner.ApplyFlags(flags)
}

func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) {
	if d == nil {
		return
	}
	d.traceElemOut = out
}

func (d *PktDecode) Write(indexSOP ocsd.TrcIndex, pkt *etmv4.TracePacket) error {
	d.lastPacketIndex = indexSOP
	if indexSOP != 0 {
		d.sawActivity = true
	}
	return d.inner.Write(indexSOP, pkt)
}

func (d *PktDecode) Close() error {
	return d.inner.Close()
}

func (d *PktDecode) Flush() error {
	return d.inner.Flush()
}

func (d *PktDecode) Reset(indexSOP ocsd.TrcIndex) error {
	return d.inner.Reset(indexSOP)
}

func (d *PktDecode) NextSequenced() (uint64, *ocsd.TraceElement, error) {
	if len(d.pendingElements) == 0 {
		return 0, nil, io.EOF
	}
	e := d.pendingElements[0]
	d.pendingElements = d.pendingElements[1:]
	elem := e.elem
	elem.Index = e.index
	elem.TraceID = e.traceID
	return e.seq, &elem, nil
}

func (d *PktDecode) Next() (*ocsd.TraceElement, error) {
	_, elem, err := d.NextSequenced()
	return elem, err
}

func cloneTraceElement(elem *ocsd.TraceElement) ocsd.TraceElement {
	clone := *elem
	if elem.PtrExtendedData != nil {
		clone.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return clone
}
