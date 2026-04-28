package ete

import (
	"bytes"
	"errors"
	"io"
	"iter"
	"testing"

	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

type dummyMem struct{}

func (d *dummyMem) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	return 0, nil, nil
}
func (d *dummyMem) InvalidateMemAccCache(csTraceID uint8) {}

type dummyInstr struct{}

func (d *dummyInstr) DecodeInstruction(instrInfo *ocsd.InstrInfo) error { return nil }

type stubPacketReader struct {
	packets []etmv4.Packet
	errs    []error
	pos     int
}

func (r *stubPacketReader) NextPacket() (etmv4.Packet, error) {
	if r.pos < len(r.errs) && r.errs[r.pos] != nil {
		err := r.errs[r.pos]
		r.pos++
		return etmv4.Packet{}, err
	}
	if r.pos < len(r.packets) {
		pkt := r.packets[r.pos]
		r.pos++
		return pkt, nil
	}
	if r.pos < len(r.errs) {
		err := r.errs[r.pos]
		r.pos++
		return etmv4.Packet{}, err
	}
	return etmv4.Packet{}, io.EOF
}

func (r *stubPacketReader) Packets() iter.Seq2[etmv4.Packet, error] {
	return ocsd.GeneratePackets(r.NextPacket)
}

func TestCreatePktProcAndDecode(t *testing.T) {
	if proc := NewProcessor(NewConfig()); proc == nil {
		t.Fatalf("NewProcessor returned nil")
	}

	dec, err := NewPktDecode(NewConfig())
	if err != nil {
		t.Fatalf("NewPktDecode err=%v", err)
	}
	if dec == nil {
		t.Fatalf("NewPktDecode returned nil")
	}
}

func TestTypedPipelineConstructors(t *testing.T) {
	tests := []struct {
		name       string
		construct  func() (*etmv4.Processor, *PktDecode, error)
		wantSource bool
	}{
		{
			name: "default",
			construct: func() (*etmv4.Processor, *PktDecode, error) {
				return NewConfiguredPipeline(3, NewConfig())
			},
			wantSource: true,
		},
		{
			name: "deps nil",
			construct: func() (*etmv4.Processor, *PktDecode, error) {
				return NewConfiguredPipelineWithDeps(4, NewConfig(), nil, nil)
			},
			wantSource: true,
		},
		{
			name: "deps present",
			construct: func() (*etmv4.Processor, *PktDecode, error) {
				return NewConfiguredPipelineWithDeps(5, NewConfig(), &dummyMem{}, &dummyInstr{})
			},
			wantSource: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc, dec, err := tt.construct()
			if err != nil {
				t.Fatalf("constructor returned error: %v", err)
			}
			if proc == nil || dec == nil {
				t.Fatalf("constructor returned nil outputs")
			}
			if tt.wantSource && dec.Source != proc {
				t.Fatalf("expected decoder source to be injected processor")
			}
		})
	}

	if procOnly := NewProcessor(nil); procOnly == nil {
		t.Fatalf("expected default-config processor for nil config, got nil")
	}
	assertConstructorError(t, ocsd.ErrInvalidParamVal, func() error {
		dec, err := NewPktDecode(nil)
		if dec != nil {
			t.Fatalf("expected nil decoder, got %v", dec)
		}
		return err
	})
	assertConstructorError(t, ocsd.ErrInvalidParamVal, func() error {
		proc, dec, err := NewConfiguredPipeline(0, nil)
		if proc != nil || dec != nil {
			t.Fatalf("expected nil outputs, got proc=%v dec=%v", proc, dec)
		}
		return err
	})
}

func assertConstructorError(t *testing.T, want error, fn func() error) {
	t.Helper()
	if err := fn(); !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
}

func TestNewProcessorWithReaderSupportsNextPacket(t *testing.T) {
	proc := NewProcessor(NewConfig(), bytes.NewReader([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
		0x04,
	}))

	assertNextPacketType(t, proc, etmv4.PktAsync)
	assertNextPacketType(t, proc, etmv4.PktTraceOn)

	_, err := proc.NextPacket()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after draining packet reader, got %v", err)
	}
}

func assertNextPacketType(t *testing.T, proc *etmv4.Processor, want etmv4.PktType) {
	t.Helper()
	pkt, err := proc.NextPacket()
	if err != nil {
		t.Fatalf("unexpected packet error: %v", err)
	}
	if pkt.Type != want {
		t.Fatalf("expected packet type %v, got %v", want, pkt.Type)
	}
}

func TestNextSequencedReturnsErrWaitWithoutTearingDownSource(t *testing.T) {
	d := newTestDecoder(t)
	source := &stubPacketReader{errs: []error{ocsd.ErrWait}}
	d.Source = source

	seq, elem, err := d.NextSequenced()
	if !errors.Is(err, ocsd.ErrWait) {
		t.Fatalf("expected ErrWait, got seq=%d elem=%v err=%v", seq, elem, err)
	}
	if d.Source != source {
		t.Fatalf("expected source to remain attached after ErrWait")
	}
	if d.pullEOFDone {
		t.Fatalf("did not expect EOF teardown after ErrWait")
	}
	if len(d.pendingElements) != 0 {
		t.Fatalf("expected no pending elements after ErrWait, got %d", len(d.pendingElements))
	}
}

func TestNextSequencedEOFTeardownClosesSourceOnce(t *testing.T) {
	d := newTestDecoder(t)
	d.Source = &stubPacketReader{errs: []error{io.EOF}}

	seq, elem, err := d.NextSequenced()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got seq=%d elem=%v err=%v", seq, elem, err)
	}
	if d.Source != nil {
		t.Fatalf("expected source to be detached after EOF teardown")
	}
	if !d.pullEOFDone {
		t.Fatalf("expected EOF teardown to mark pullEOFDone")
	}

	seq, elem, err = d.NextSequenced()
	if err != nil {
		t.Fatalf("expected close-generated element after teardown, got seq=%d elem=%v err=%v", seq, elem, err)
	}
	assertTraceElement(t, elem, 0, 0, ocsd.GenElemEOTrace)
	if seq == 0 {
		t.Fatalf("expected non-zero sequence")
	}

	seq, elem, err = d.NextSequenced()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected repeated io.EOF after draining teardown element, got seq=%d elem=%v err=%v", seq, elem, err)
	}
}

func TestNextSequencedEOFReturnsBeforeDrainingQueuedElements(t *testing.T) {
	d := newTestDecoder(t)
	d.pendingElements = []traceElemEvent{{
		seq:     7,
		index:   11,
		traceID: 3,
		elem:    ocsd.TraceElement{ElemType: ocsd.GenElemEvent},
	}}
	d.Source = &stubPacketReader{errs: []error{io.EOF}}

	seq, elem, err := d.NextSequenced()
	if err != nil {
		t.Fatalf("expected queued element before touching source EOF, got seq=%d elem=%v err=%v", seq, elem, err)
	}
	if seq != 7 {
		t.Fatalf("unexpected sequence: got %d want 7", seq)
	}
	assertTraceElement(t, elem, 11, 3, ocsd.GenElemEvent)

	seq, elem, err = d.NextSequenced()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on source teardown, got seq=%d elem=%v err=%v", seq, elem, err)
	}
	if d.Source != nil {
		t.Fatalf("expected source to be detached after EOF teardown")
	}
	if !d.pullEOFDone {
		t.Fatalf("expected EOF teardown to mark pullEOFDone")
	}

	seq, elem, err = d.NextSequenced()
	if err != nil {
		t.Fatalf("expected teardown-generated element to remain queued after EOF, got seq=%d elem=%v err=%v", seq, elem, err)
	}
	assertTraceElement(t, elem, 0, 0, ocsd.GenElemEOTrace)
}

func newTestDecoder(t *testing.T) *PktDecode {
	t.Helper()
	d, err := NewPktDecode(NewConfig())
	if err != nil {
		t.Fatalf("NewPktDecode err=%v", err)
	}
	return d
}

func assertTraceElement(t *testing.T, elem *ocsd.TraceElement, index ocsd.TrcIndex, traceID uint8, typ ocsd.GenElemType) {
	t.Helper()
	if elem == nil {
		t.Fatalf("expected trace element, got nil")
	}
	if elem.Index != index || elem.TraceID != traceID || elem.ElemType != typ {
		t.Fatalf("unexpected trace element: idx=%d trace=%d type=%v", elem.Index, elem.TraceID, elem.ElemType)
	}
}
