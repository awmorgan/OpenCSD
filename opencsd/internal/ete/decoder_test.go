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

// Dummy implementations for push-mode pipeline wiring tests
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

// Packets returns an empty iterator when no packets are available.
func (r *stubPacketReader) Packets() iter.Seq2[etmv4.Packet, error] {
	return func(yield func(etmv4.Packet, error) bool) {}
}

func TestCreatePktProcAndDecode(t *testing.T) {
	cfg := NewConfig()

	proc := NewProcessor(cfg)
	if proc == nil {
		t.Fatalf("NewProcessor returned nil")
	}

	dec, err := NewPktDecode(cfg)
	if err != nil {
		t.Fatalf("NewPktDecode err=%v", err)
	}
	if dec == nil {
		t.Fatalf("NewPktDecode returned nil")
	}
}

func TestTypedPipelineConstructors(t *testing.T) {
	proc, dec, err := NewConfiguredPipeline(3, NewConfig())
	if err != nil {
		t.Fatalf("NewConfiguredPipeline err=%v", err)
	}
	if proc == nil || dec == nil {
		t.Fatalf("NewConfiguredPipeline returned nil outputs")
	}
	if dec.Source != proc {
		t.Fatalf("expected NewConfiguredPipeline decoder source to be injected processor")
	}

	procWithDeps, decWithDeps, err := NewConfiguredPipelineWithDeps(4, NewConfig(), nil, nil)
	if err != nil {
		t.Fatalf("NewConfiguredPipelineWithDeps err=%v", err)
	}
	if procWithDeps == nil || decWithDeps == nil {
		t.Fatalf("NewConfiguredPipelineWithDeps returned nil outputs")
	}
	if decWithDeps.Source != procWithDeps {
		t.Fatalf("expected NewConfiguredPipelineWithDeps decoder source to be injected processor when deps are nil")
	}

	// When dependencies are present, should use push wiring (source is nil)
	procPush, decPush, err := NewConfiguredPipelineWithDeps(5, NewConfig(), &dummyMem{}, &dummyInstr{})
	if err != nil {
		t.Fatalf("NewConfiguredPipelineWithDeps (push) err=%v", err)
	}
	if procPush == nil || decPush == nil {
		t.Fatalf("NewConfiguredPipelineWithDeps (push) returned nil outputs")
	}
	if decPush.Source != procPush {
		t.Fatalf("expected NewConfiguredPipelineWithDeps decoder source to be injected processor even when dependencies are present")
	}
	// (Cannot check procPush.SetPktOut side effect directly)

	typeCheck := func(any any) {}
	typeCheck(procPush)
	typeCheck(decPush)

	if procOnly := NewProcessor(nil); procOnly == nil {
		t.Fatalf("expected default-config processor for nil config, got nil")
	}
	if decOnly, err := NewPktDecode(nil); decOnly != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config decoder constructor failure, got dec=%v err=%v", decOnly, err)
	}
	if procOnly, decOnly, err := NewConfiguredPipeline(0, nil); procOnly != nil || decOnly != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config pipeline constructor failure, got proc=%v dec=%v err=%v", procOnly, decOnly, err)
	}
}

func isErrorCode(err error, code error) bool {
	return errors.Is(err, code)
}

func TestNewProcessorWithReaderSupportsNextPacket(t *testing.T) {
	proc := NewProcessor(NewConfig(), bytes.NewReader([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
		0x04,
	}))

	pkt, err := proc.NextPacket()
	if err != nil {
		t.Fatalf("unexpected first packet error: %v", err)
	}
	if pkt.Type != etmv4.PktAsync {
		t.Fatalf("expected first packet type %v, got %v", etmv4.PktAsync, pkt.Type)
	}

	pkt, err = proc.NextPacket()
	if err != nil {
		t.Fatalf("unexpected second packet error: %v", err)
	}
	if pkt.Type != etmv4.PktTraceOn {
		t.Fatalf("expected second packet type %v, got %v", etmv4.PktTraceOn, pkt.Type)
	}

	_, err = proc.NextPacket()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after draining packet reader, got %v", err)
	}
}

func TestNextSequencedReturnsErrWaitWithoutTearingDownSource(t *testing.T) {
	d, err := NewPktDecode(NewConfig())
	if err != nil {
		t.Fatalf("NewPktDecode err=%v", err)
	}
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
	d, err := NewPktDecode(NewConfig())
	if err != nil {
		t.Fatalf("NewPktDecode err=%v", err)
	}
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
	if seq == 0 || elem == nil {
		t.Fatalf("expected close-generated element after teardown, got seq=%d elem=%v", seq, elem)
	}
	if elem.ElemType != ocsd.GenElemEOTrace {
		t.Fatalf("expected GenElemEOTrace after teardown, got %v", elem.ElemType)
	}

	seq, elem, err = d.NextSequenced()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected repeated io.EOF after draining teardown element, got seq=%d elem=%v err=%v", seq, elem, err)
	}
}

func TestNextSequencedEOFReturnsBeforeDrainingQueuedElements(t *testing.T) {
	d, err := NewPktDecode(NewConfig())
	if err != nil {
		t.Fatalf("NewPktDecode err=%v", err)
	}
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
	if seq != 7 || elem == nil || elem.Index != 11 || elem.TraceID != 3 || elem.ElemType != ocsd.GenElemEvent {
		t.Fatalf("unexpected queued element after drain: seq=%d elem=%v", seq, elem)
	}

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
	if elem == nil || elem.ElemType != ocsd.GenElemEOTrace {
		t.Fatalf("expected queued GenElemEOTrace after EOF, got seq=%d elem=%v", seq, elem)
	}
}
