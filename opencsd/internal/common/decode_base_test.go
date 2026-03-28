package common

import (
	"opencsd/internal/ocsd"
	"testing"
)

func TestDecoderBase(t *testing.T) {
	b := &DecoderBase{}
	b.Init("testDecode", nil)

	if b.Name != "testDecode" {
		t.Errorf("expected name testDecode, got %s", b.Name)
	}

	b.ConfigureSupportedOpModes(0x0F)
	if err := b.ConfigureComponentOpMode(0x03); err != nil {
		t.Errorf("expected OK, got %v", err)
	}
	if b.ComponentOpMode() != 0x03 {
		t.Errorf("expected op mode 0x03, got 0x%x", b.ComponentOpMode())
	}
	if b.SupportedOpModes() != 0x0F {
		t.Errorf("expected supported modes 0x0F, got 0x%x", b.SupportedOpModes())
	}

	// Flags outside supported range should be masked out
	if err := b.ConfigureComponentOpMode(0x10); err != nil {
		t.Errorf("expected OK after masking, got %v", err)
	}
	if b.ComponentOpMode() != 0x00 {
		t.Errorf("expected 0x00 after masking unsupported flags, got 0x%x", b.ComponentOpMode())
	}

	// DecodeNotReadyReason — no config yet
	if reason := b.DecodeNotReadyReason(); reason == "" {
		t.Errorf("expected non-empty not-ready reason before ConfigInitOK")
	}

	// Wire a trace element output
	elemIn := &myTrcGenElemIn{}
	b.TraceElemOut = elemIn
	b.ConfigInitOK = true
	b.UsesMemAccess = false
	b.UsesIDecode = false

	if reason := b.DecodeNotReadyReason(); reason != "" {
		t.Errorf("expected empty not-ready reason, got: %s", reason)
	}

	elem := ocsd.NewTraceElement()
	resp := b.OutputTraceElement(123, elem)
	if resp != ocsd.RespCont {
		t.Errorf("OutputTraceElement resp = %v, want RespCont", resp)
	}

	b.IndexCurrPkt = 42
	resp = b.OutputTraceElementIdx(99, 123, elem)
	if resp != ocsd.RespCont || elemIn.lastIndex != 99 {
		t.Errorf("OutputTraceElementIdx failed: resp=%v lastIndex=%v", resp, elemIn.lastIndex)
	}

	// AccessMemory / InstrDecodeCall when interfaces unused
	b.UsesMemAccess = false
	b.UsesIDecode = false
	_, _, memErr := b.AccessMemory(0x1000, 123, ocsd.MemSpaceAny, 4)
	if memErr != ocsd.ErrDcdInterfaceUnused {
		t.Errorf("expected ErrDcdInterfaceUnused for AccessMemory, got %v", memErr)
	}
	var instr ocsd.InstrInfo
	if err := b.InstrDecodeCall(&instr); err != ocsd.ErrDcdInterfaceUnused {
		t.Errorf("expected ErrDcdInterfaceUnused for InstrDecodeCall, got %v", err)
	}
	if err := b.InvalidateMemAccCache(0); err != ocsd.ErrDcdInterfaceUnused {
		t.Errorf("expected ErrDcdInterfaceUnused for InvalidateMemAccCache, got %v", err)
	}
}

func TestProcBase(t *testing.T) {
	b := &ProcBase[any]{}
	b.Init("testProc", nil)

	if b.Name != "testProc" {
		t.Errorf("expected name testProc, got %s", b.Name)
	}

	b.ConfigureSupportedOpModes(0x0F)
	if err := b.ConfigureComponentOpMode(0x05); err != nil {
		t.Errorf("expected OK, got %v", err)
	}
	if b.ComponentOpMode() != 0x05 {
		t.Errorf("expected op mode 0x05, got 0x%x", b.ComponentOpMode())
	}

	// Stats not yet initialized
	_, errCode := b.StatsBlock()
	if errCode != ocsd.ErrNotInit {
		t.Errorf("expected ErrNotInit before StatsInit, got %v", errCode)
	}

	b.StatsInit()
	b.StatsAddTotalCount(100)
	b.StatsAddUnsyncCount(5)
	b.StatsAddBadSeqCount(2)
	b.StatsAddBadHdrCount(1)

	stats, errCode := b.StatsBlock()
	if errCode != nil {
		t.Errorf("expected OK after StatsInit, got %v", errCode)
	}
	if stats.ChannelTotal != 100 {
		t.Errorf("expected ChannelTotal=100, got %d", stats.ChannelTotal)
	}
	if stats.ChannelUnsynced != 5 {
		t.Errorf("expected ChannelUnsynced=5, got %d", stats.ChannelUnsynced)
	}
	if stats.BadSequenceErrs != 2 {
		t.Errorf("expected BadSequenceErrs=2, got %d", stats.BadSequenceErrs)
	}
	if stats.BadHeaderErrs != 1 {
		t.Errorf("expected BadHeaderErrs=1, got %d", stats.BadHeaderErrs)
	}

	b.ResetStats()
	if b.Stats.ChannelTotal != 0 {
		t.Errorf("expected ChannelTotal=0 after reset, got %d", b.Stats.ChannelTotal)
	}
}

// myTrcGenElemIn is a test sink for GenElemProcessor.
type myTrcGenElemIn struct {
	lastIndex ocsd.TrcIndex
	lastID    uint8
}

func (m *myTrcGenElemIn) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	m.lastIndex = indexSOP
	m.lastID = trcChanID
	return ocsd.RespCont
}
