package stm

import (
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type testTrcElemIn struct {
	elements []common.TraceElement
}

func (t *testTrcElemIn) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *common.TraceElement) ocsd.DatapathResp {
	t.elements = append(t.elements, *elem)
	return ocsd.RespCont
}

type StmStreamBuilder struct {
	data      []byte
	hasNibble bool
	nibble    byte
}

func (b *StmStreamBuilder) AddNibble(n byte) {
	if !b.hasNibble {
		b.nibble = n & 0xF
		b.hasNibble = true
	} else {
		b.data = append(b.data, b.nibble|((n&0xF)<<4))
		b.hasNibble = false
	}
}

func (b *StmStreamBuilder) AddNibbles(n ...byte) {
	for _, v := range n {
		b.AddNibble(v)
	}
}

func (b *StmStreamBuilder) Flush() {
	if b.hasNibble {
		b.data = append(b.data, b.nibble) // upper nibble defaults to 0 (Null)
		b.hasNibble = false
	}
}

func TestSTMPrehensive(t *testing.T) {
	config := NewConfig()
	config.SetTraceID(0x10)

	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config)
	dec := manager.CreatePktDecode(0, config)

	// Op mode test
	proc.SetComponentOpMode(ocsd.OpflgPktprocUnsyncOnBadPkts)

	proc.PktOutI.Attach(dec)
	outReceiver := &testTrcElemIn{}
	dec.TraceElemOut.Attach(outReceiver)

	sb := &StmStreamBuilder{}

	// 1) ASYNC
	for i := 0; i < 21; i++ {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)

	// 2) VERSION 3 (Nat binary TS)
	sb.AddNibbles(0xF, 0x0, 0x0, 0x3)
	// VERSION 4 (Gray TS) to test coverage
	sb.AddNibbles(0xF, 0x0, 0x0, 0x4)

	// Reset to VERSION 3
	sb.AddNibbles(0xF, 0x0, 0x0, 0x3)

	// 1N operations
	sb.AddNibbles(0x0)                                                                                 // NULL
	sb.AddNibbles(0x1, 0xA, 0xB)                                                                       // M8 (0xBA)
	sb.AddNibbles(0x2, 0xC, 0xD)                                                                       // MERR (0xDC)
	sb.AddNibbles(0x3, 0xE, 0xF)                                                                       // C8 (0xFE)
	sb.AddNibbles(0x4, 0x1, 0x2)                                                                       // D8 (0x21)
	sb.AddNibbles(0x5, 0x1, 0x2, 0x3, 0x4)                                                             // D16 (0x4321)
	sb.AddNibbles(0x6, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8)                                         // D32
	sb.AddNibbles(0x7, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8) // D64

	// TS generation helper (size A = 10 nibbles)
	addTS := func() {
		sb.AddNibbles(0xA, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0)
	}

	sb.AddNibbles(0x8, 0x1, 0x2)
	addTS() // D8MTS
	sb.AddNibbles(0x9, 0x1, 0x2, 0x3, 0x4)
	addTS() // D16MTS
	sb.AddNibbles(0xA, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8)
	addTS() // D32MTS
	sb.AddNibbles(0xB, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8)
	addTS()                 // D64MTS
	sb.AddNibbles(0xC, 0x5) // D4
	sb.AddNibbles(0xD, 0x5)
	addTS() // D4MTS
	sb.AddNibbles(0xE)
	addTS() // FLAGTS

	// 2N operations
	sb.AddNibbles(0xF, 0x2, 0xA, 0xB)           // GERR
	sb.AddNibbles(0xF, 0x3, 0x1, 0x2, 0x3, 0x4) // C16
	sb.AddNibbles(0xF, 0x4, 0x1, 0x2)
	addTS() // D8TS
	sb.AddNibbles(0xF, 0x5, 0x1, 0x2, 0x3, 0x4)
	addTS() // D16TS
	sb.AddNibbles(0xF, 0x6, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8)
	addTS() // D32TS
	sb.AddNibbles(0xF, 0x7, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8)
	addTS()                                                                                                 // D64TS
	sb.AddNibbles(0xF, 0x8, 0x1, 0x2)                                                                       // D8M
	sb.AddNibbles(0xF, 0x9, 0x1, 0x2, 0x3, 0x4)                                                             // D16M
	sb.AddNibbles(0xF, 0xA, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8)                                         // D32M
	sb.AddNibbles(0xF, 0xB, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8) // D64M
	sb.AddNibbles(0xF, 0xC, 0x5)
	addTS()                      // D4TS
	sb.AddNibbles(0xF, 0xD, 0x5) // D4M
	sb.AddNibbles(0xF, 0xE)      // FLAG

	// 3N operations
	sb.AddNibbles(0xF, 0x0, 0x1)
	addTS()                                // NULLTS
	sb.AddNibbles(0xF, 0x0, 0x6, 0x1, 0x2) // TRIG
	sb.AddNibbles(0xF, 0x0, 0x7, 0x3, 0x4)
	addTS()                                                              // TRIGTS
	sb.AddNibbles(0xF, 0x0, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8) // FREQ

	// ASYNC packet mid-stream (alignment sync)
	for i := 0; i < 21; i++ {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)

	// Error checks (reserved headers)
	// reserved 1N actually handled directly, this will throw BadSequence/InvalidHdr
	// We'll flush the existing to not mess up sequence
	sb.Flush()

	proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(sb.data)), nil)

	if len(outReceiver.elements) == 0 {
		t.Error("Expected to receive parsed trace elements")
	}
}

func TestSTMErrorCases(t *testing.T) {
	config := NewConfig()
	proc := NewPktProc(0)
	proc.SetProtocolConfig(config)

	// Error case 1: ASYNC with invalid padding
	sb := &StmStreamBuilder{}
	for i := 0; i < 21; i++ {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x1) // invalid ASYNC sync char
	sb.Flush()
	_, resp := proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response for invalid ASYNC by default")
	}

	// Reset and Try reserved opcode in 1N
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	sb = &StmStreamBuilder{}
	sb.AddNibbles(0xF) // wait sync needs data, so we won't get it to complain unless it's in sync.
	// Actually to be in sync, it needs to see ASYNC.
	for i := 0; i < 21; i++ {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)
	sb.AddNibbles(0xF, 0x1) // Reserved 0xF1 opcode
	sb.Flush()
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response for reserved opcode by default")
	}

	// Try with bad packet handling component mode
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	proc.SetComponentOpMode(ocsd.OpflgPktprocErrBadPkts)
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	// Should be fatal if ErrBadPkts mode is set
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for reserved opcode when bad packet throwing is enabled. Mode=%x, Resp=%v", proc.ComponentOpMode(), resp)
	}

	// Try gray TS
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	sb = &StmStreamBuilder{}
	for i := 0; i < 21; i++ {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)
	sb.AddNibbles(0xF, 0x0, 0x0, 0x4) // VERSION 4 (Gray)
	sb.AddNibbles(0x0)                // NULL
	// TS Gray (size A)
	sb.AddNibbles(0xF, 0x0, 0x1, 0xA, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0)

	// TS size D (14 nibbles)
	sb.AddNibbles(0xF, 0x0, 0x1, 0xD, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4)

	// TS size E (16 nibbles)
	sb.AddNibbles(0xF, 0x0, 0x1, 0xE, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6)

	// TS size F (invalid) - will throw BadSequence, but since ErrBadPkts is set, it will be fatal
	sb.AddNibbles(0xF, 0x0, 0x1, 0xF)
	sb.Flush()

	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for invalid TS size. Mode=%x, Resp=%v", proc.ComponentOpMode(), resp)
	}

	// Try reserved F0n
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	sb = &StmStreamBuilder{}
	for i := 0; i < 21; i++ {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)
	sb.AddNibbles(0xF, 0x0, 0x1) // Reserved F01
	sb.Flush()
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for reserved F0n opcode")
	}
}

func TestSTMPacketString(t *testing.T) {
	pkt := &Packet{}
	pkt.InitStartState()
	if pkt.String() != "NOTSYNC:STM not synchronised" {
		t.Errorf("Unexpected string for initial state: %s", pkt.String())
	}

	pkt.SetPacketType(PktD8, false)
	pkt.SetD8Payload(0xAB)
	str := pkt.String()
	if str != "D8:8 bit data; Data=0xAB" {
		t.Errorf("Unexpected formatting for D8: %s", str)
	}

	pkt.SetPacketType(PktBadSequence, false)
	pkt.ErrType = PktD32
	if pkt.String() != "BAD_SEQUENCE:Invalid sequence in packet[D32]" {
		t.Errorf("Unexpected formatting: %s", pkt.String())
	}

	pkt.SetPacketType(PktFreq, false)
	pkt.SetD32Payload(1000)
	if pkt.String() != "FREQ:Frequency packet; Freq=1000Hz" {
		t.Errorf("Unexpected formatting: %s", pkt.String())
	}
}

func TestSTMConfig(t *testing.T) {
	cfg := NewConfig()
	cfg.SetTraceID(0x77)
	if cfg.TraceID() != 0x77 {
		t.Errorf("TraceID mismatch")
	}
	cfg.SetHWTraceFeat(HWEventEnabled)
	if !cfg.HWTraceEn() {
		t.Errorf("HWTraceEn mismatch")
	}
	cfg.SetHWTraceFeat(HWEventUseRegisters)
	if cfg.HWTraceEn() {
		t.Errorf("HWTraceEn should be false")
	}
	cfg.RegFeat1R = 0x80000
	cfg.RegTCSR = 0x8
	cfg.SetHWTraceFeat(HWEventUseRegisters)
	if !cfg.HWTraceEn() {
		t.Errorf("HWTraceEn should be true")
	}
	_ = cfg.MaxMasterIdx()
	_ = cfg.MaxChannelIdx()
	_ = cfg.HWTraceMasterIdx()
}

func TestSTMOtherCoverage(t *testing.T) {
	config := NewConfig()
	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, config)
	dec := manager.CreatePktDecode(0, config)

	proc.TraceDataIn(ocsd.OpFlush, 0, nil)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)

	dec.PacketDataIn(ocsd.OpFlush, 0, nil)
	dec.PacketDataIn(ocsd.OpReset, 0, nil)

	pkt := &Packet{}
	pkt.InitNextPacket()
	pkt.SetPacketType(PktBadSequence, false)
	if !pkt.IsBadPacket() {
		t.Errorf("Expected IsBadPacket to be true")
	}
}
