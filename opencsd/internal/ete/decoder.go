package ete

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"sync/atomic"

	"opencsd/internal/common"
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

type traceElemEvent struct {
	seq     uint64
	index   ocsd.TrcIndex
	traceID uint8
	elem    ocsd.TraceElement
}

type ElementCallback func(seq uint64, index ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error

var queuedTraceElemSeq atomic.Uint64

type SequencedTraceIterator interface {
	NextSequenced() (uint64, *ocsd.TraceElement, error)
}

type PktDecode struct {
	inner           *etmv4.PktDecode
	pendingElements []traceElemEvent
	lastPacketIndex ocsd.TrcIndex
	lastElemIndex   ocsd.TrcIndex
	sawActivity     bool
	pullEOFDone     bool
	OutSink         ElementCallback

	// Source is the pull-based packet reader injected at construction time.
	// May be nil when the push-based Write path is used instead.
	Source ocsd.PacketReader[etmv4.Packet]
}

func NewPktDecode(cfg *Config) (*PktDecode, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	inner, err := etmv4.NewPktDecode(cfg.ToETMv4Config())
	if err != nil {
		return nil, err
	}
	return &PktDecode{inner: inner}, nil
}

func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	return nil
}

// NewConfiguredPktDecodeWithDeps creates an ETE decoder and injects dependencies.
// source is the pull-based PacketReader to use; pass nil to use the push-based Write path.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode, source ocsd.PacketReader[etmv4.Packet], outSink ElementCallback) (*PktDecode, error) {
	_ = instID
	decoder, err := NewPktDecode(cfg)
	if err != nil {
		return nil, err
	}
	decoder.SetInterfaces(mem, instr)
	decoder.Source = source
	decoder.OutSink = outSink
	return decoder, nil
}

// SetInterfaces updates the optional memory and instruction decode dependencies.
func (d *PktDecode) SetInterfaces(mem common.TargetMemAccess, instr common.InstrDecode) {
	if d == nil || d.inner == nil {
		return
	}
	d.inner.MemAccess = mem
	d.inner.InstrDecode = instr
}

// NewConfiguredPipeline creates and wires a typed ETE processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*etmv4.Processor, *PktDecode, error) {
	return newConfiguredPipeline(instID, cfg, nil, nil, false)
}

// NewConfiguredPipelineWithDeps creates and wires an ETE processor/decoder pair with dependencies.
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*etmv4.Processor, *PktDecode, error) {
	return newConfiguredPipeline(instID, cfg, mem, instr, true)
}

func newConfiguredPipeline(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode, attachPush bool) (*etmv4.Processor, *PktDecode, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, nil, err
	}

	proc := NewProcessor(cfg)
	decoder, err := NewConfiguredPktDecodeWithDeps(instID, cfg, mem, instr, proc, nil)
	if err != nil {
		return nil, nil, err
	}
	if attachPush {
		proc.SetPktOut(&pushSink{d: decoder})
	}
	return proc, decoder, nil
}

func (d *PktDecode) ApplyFlags(flags uint32) error {
	if d == nil || d.inner == nil {
		return ocsd.ErrNotInit
	}
	return d.inner.ApplyFlags(flags)
}

func (d *PktDecode) traceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	if d == nil || elem == nil {
		return nil
	}

	queueIndex := d.queueIndex(indexSOP, elem)
	queued := cloneTraceElement(elem)
	queued.TraceID = trcChanID

	seq := queuedTraceElemSeq.Add(1)
	if d.OutSink != nil {
		if err := d.OutSink(seq, queueIndex, trcChanID, &queued); err != nil {
			return err
		}
	}

	d.pendingElements = append(d.pendingElements, traceElemEvent{
		seq:     seq,
		index:   queueIndex,
		traceID: queued.TraceID,
		elem:    queued,
	})
	return nil
}

func (d *PktDecode) queueIndex(indexSOP ocsd.TrcIndex, elem *ocsd.TraceElement) ocsd.TrcIndex {
	if indexSOP != 0 {
		d.lastElemIndex = indexSOP
		d.sawActivity = true
		return indexSOP
	}
	if elem.ElemType != ocsd.GenElemEOTrace {
		return 0
	}
	if d.lastElemIndex != 0 {
		return d.lastElemIndex + 1
	}
	return d.lastPacketIndex
}

// drainInner pulls all buffered elements from the inner ETMv4 decoder and
// processes them through traceElemIn for index fixup and buffering.
func (d *PktDecode) drainInner() error {
	for {
		idx, trcChanID, elem, err := d.inner.NextElement()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := d.traceElemIn(idx, trcChanID, &elem); err != nil {
			return err
		}
	}
}

// pushSink adapts PktDecode to the ocsd.PacketProcessor[etmv4.TracePacket]
// interface for push-mode pipelines without exposing a public Write on PktDecode itself.
type pushSink struct {
	d *PktDecode
}

func (p *pushSink) Write(indexSOP ocsd.TrcIndex, pkt *etmv4.TracePacket) error {
	p.d.recordPacketIndex(indexSOP)
	if err := p.d.inner.Write(indexSOP, pkt); err != nil {
		return err
	}
	return p.d.drainInner()
}

func (p *pushSink) Close() error                       { return p.d.Close() }
func (p *pushSink) Flush() error                       { return p.d.Flush() }
func (p *pushSink) Reset(indexSOP ocsd.TrcIndex) error { return p.d.Reset(indexSOP) }

func (d *PktDecode) recordPacketIndex(index ocsd.TrcIndex) {
	d.lastPacketIndex = index
	if index != 0 {
		d.sawActivity = true
	}
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
	d.pendingElements = d.pendingElements[:0]
	d.lastPacketIndex = 0
	d.lastElemIndex = 0
	d.sawActivity = false
	d.pullEOFDone = false
	return d.inner.Reset(indexSOP)
}

// NextSequenced returns the next queued trace element with its sequence number,
// or EOF if none are available. When a pull-based Source is set and no push
// sink is wired, it fetches the next packet, decodes it, and returns the first
// resulting element.
func (d *PktDecode) NextSequenced() (uint64, *ocsd.TraceElement, error) {
	if e, ok := d.popPendingElement(); ok {
		return e.seq, elementFromEvent(e), nil
	}

	if err := d.fillPendingFromSource(); err != nil {
		return 0, nil, err
	}

	if e, ok := d.popPendingElement(); ok {
		return e.seq, elementFromEvent(e), nil
	}
	return 0, nil, io.EOF
}

func (d *PktDecode) fillPendingFromSource() error {
	for len(d.pendingElements) == 0 && d.Source != nil {
		pkt, err := d.Source.NextPacket()
		switch {
		case errors.Is(err, io.EOF):
			return d.handleSourceEOF()
		case errors.Is(err, ocsd.ErrWait):
			return ocsd.ErrWait
		case err != nil:
			d.Source = nil
			return err
		}

		if err := d.writePacket(&pkt); err != nil {
			return err
		}
	}
	return nil
}

func (d *PktDecode) writePacket(pkt *etmv4.Packet) error {
	d.recordPacketIndex(pkt.Index)
	if err := d.inner.Write(pkt.Index, pkt); err != nil {
		return err
	}
	return d.drainInner()
}

func (d *PktDecode) handleSourceEOF() error {
	d.Source = nil
	if d.pullEOFDone {
		return io.EOF
	}
	d.pullEOFDone = true
	if err := d.Close(); err != nil {
		return err
	}
	return io.EOF
}

func (d *PktDecode) popPendingElement() (traceElemEvent, bool) {
	if len(d.pendingElements) == 0 {
		return traceElemEvent{}, false
	}
	e := d.pendingElements[0]
	d.pendingElements = d.pendingElements[1:]
	return e, true
}

func elementFromEvent(e traceElemEvent) *ocsd.TraceElement {
	elem := e.elem
	elem.Index = e.index
	elem.TraceID = e.traceID
	return &elem
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

// Elements provides a standard Go 1.23 iterator over the trace elements.
// It wraps the legacy pull-based Next() method.
func (d *PktDecode) Elements() iter.Seq2[*ocsd.TraceElement, error] {
	return ocsd.GenerateElements(d.Next)
}
