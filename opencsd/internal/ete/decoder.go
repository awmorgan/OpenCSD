package ete

import (
	"errors"
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
	queueIndex := indexSOP
	if queueIndex == 0 && elem.ElemType == ocsd.GenElemEOTrace {
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
	pendingElements []traceElemEvent
	lastPacketIndex ocsd.TrcIndex
	lastElemIndex   ocsd.TrcIndex
	sawActivity     bool

	// Source is the pull-based packet reader injected at construction time.
	// May be nil when the push-based Write path is used instead.
	Source ocsd.PacketReader[etmv4.Packet]
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
	return decoder, nil
}

// NewConfiguredPktDecodeWithDeps creates an ETE decoder and injects dependencies.
// source is the pull-based PacketReader to use; pass nil to use the push-based Write path.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode, source ocsd.PacketReader[etmv4.Packet]) (*PktDecode, error) {
	_ = instID
	decoder, err := NewPktDecode(cfg)
	if err != nil {
		return nil, err
	}
	decoder.inner.MemAccess = mem
	decoder.inner.InstrDecode = instr
	decoder.Source = source
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

	decoder, err := NewConfiguredPktDecodeWithDeps(instID, cfg, mem, instr, nil)
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

// drainInner pulls all buffered elements from the inner ETMv4 decoder and
// processes them through TraceElemIn for index fixup and buffering.
func (d *PktDecode) drainInner() error {
	for {
		idx, trcChanID, elem, err := d.inner.NextElement()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := d.TraceElemIn(idx, trcChanID, &elem); err != nil {
			return err
		}
	}
}

func (d *PktDecode) Write(indexSOP ocsd.TrcIndex, pkt *etmv4.TracePacket) error {
	d.lastPacketIndex = indexSOP
	if indexSOP != 0 {
		d.sawActivity = true
	}
	if err := d.inner.Write(indexSOP, pkt); err != nil {
		return err
	}
	return d.drainInner()
}

func (d *PktDecode) Close() error {
	if err := d.inner.Close(); err != nil {
		return err
	}
	return d.drainInner()
}

func (d *PktDecode) Flush() error {
	if err := d.inner.Flush(); err != nil {
		return err
	}
	return d.drainInner()
}

func (d *PktDecode) Reset(indexSOP ocsd.TrcIndex) error {
	return d.inner.Reset(indexSOP)
}

// NextSequenced returns the next queued trace element with its sequence number,
// or EOF if none are available. When a pull-based Source is set and no push
// sink is wired, it fetches the next packet, decodes it, and returns the first
// resulting element.
func (d *PktDecode) NextSequenced() (uint64, *ocsd.TraceElement, error) {
	for len(d.pendingElements) == 0 && d.Source != nil {
		pkt, err := d.Source.NextPacket()
		if errors.Is(err, io.EOF) {
			d.Source = nil
			_ = d.Close()
			break
		}
		if err != nil {
			d.Source = nil
			return 0, nil, err
		}
		if wErr := d.Write(0, &pkt); wErr != nil {
			return 0, nil, wErr
		}
	}
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
