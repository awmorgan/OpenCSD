package stm

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"opencsd/internal/ocsd"
)

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

func TestSTMEndToEndDecode(t *testing.T) {
	config := NewConfig()
	config.SetTraceID(0x10)

	proc, dec, err := NewConfiguredPipeline(0, config)
	if err != nil {
		t.Fatalf("NewConfiguredPipeline failed: %v", err)
	}

	// Op mode test
	_ = proc.ApplyFlags(ocsd.OpflgPktprocUnsyncOnBadPkts)

	sb := &StmStreamBuilder{}

	// 1) ASYNC
	for range 21 {
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
	for range 21 {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)

	// Error checks (reserved headers)
	// reserved 1N actually handled directly, this will throw BadSequence/InvalidHdr
	// We'll flush the existing to not mess up sequence
	sb.Flush()

	_, err1 := proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	res1 := ocsd.DataRespFromErr(err1)
	if !ocsd.DataRespIsCont(res1) || err1 != nil {
		t.Logf("TraceDataIn Data returned %v, err %v", res1, err1)
	}
	_, err2 := proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(sb.data)), nil)
	res2 := ocsd.DataRespFromErr(err2)
	if !ocsd.DataRespIsCont(res2) || err2 != nil {
		t.Logf("TraceDataIn EOT returned %v, err %v", res2, err2)
	}

	elemCount := 0
	for {
		_, pullErr := dec.Next()
		if errors.Is(pullErr, io.EOF) {
			break
		}
		if pullErr != nil {
			t.Fatalf("pull decode failed: %v", pullErr)
		}
		elemCount++
	}

	if elemCount == 0 {
		t.Error("Expected to receive parsed trace elements")
	}
}

func TestSTMErrorCases(t *testing.T) {
	config := NewConfig()
	proc := NewPktProc(nil)
	proc.SetProtocolConfig(config)

	// Error case 1: ASYNC with invalid padding
	sb := &StmStreamBuilder{}
	for range 21 {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x1) // invalid ASYNC sync char
	sb.Flush()
	_, err := proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp := ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response for invalid ASYNC by default")
	}

	// Reset and Try reserved opcode in 1N
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	sb = &StmStreamBuilder{}
	sb.AddNibbles(0xF) // wait sync needs data, so we won't get it to complain unless it's in sync.
	// Actually to be in sync, it needs to see ASYNC.
	for range 21 {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)
	sb.AddNibbles(0xF, 0x1) // Reserved 0xF1 opcode
	sb.Flush()
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response for reserved opcode by default")
	}

	// Try with bad packet handling component mode
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_ = proc.ApplyFlags(ocsd.OpflgPktprocErrBadPkts)
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	// Should be fatal if ErrBadPkts mode is set
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for reserved opcode when bad packet throwing is enabled. Resp=%v", resp)
	}

	// Try gray TS
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	sb = &StmStreamBuilder{}
	for range 21 {
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

	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for invalid TS size. Resp=%v", resp)
	}

	// Try reserved F0n
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	sb = &StmStreamBuilder{}
	for range 21 {
		sb.AddNibble(0xF)
	}
	sb.AddNibble(0x0)
	sb.AddNibbles(0xF, 0x0, 0x1) // Reserved F01
	sb.Flush()
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for reserved F0n opcode")
	}
}

func TestSTMPacketString(t *testing.T) {
	pkt := &Packet{}
	pkt.ResetStartState()
	if pkt.String() != "NOTSYNC:STM not synchronised" {
		t.Errorf("Unexpected string for initial state: %s", pkt.String())
	}

	pkt.SetPacketType(PktD8, false)
	pkt.Payload.D8 = 0xAB
	str := pkt.String()
	if str != "D8:8 bit data; Data=0xab" {
		t.Errorf("Unexpected formatting for D8: %s", str)
	}

	pkt.SetPacketType(PktD32, false)
	pkt.OrigType = pkt.Type
	pkt.Type = PktBadSequence
	if pkt.String() != "BAD_SEQUENCE:Invalid sequence in packet[D32]" {
		t.Errorf("Unexpected formatting: %s", pkt.String())
	}
	pkt.Type = PktD8

	pkt.SetPacketType(PktFreq, false)
	pkt.Payload.D32 = 1000
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

func TestSTMFlushResetAndBadPacketClassification(t *testing.T) {
	config := NewConfig()
	proc, err := NewConfiguredPktProc(0, config)
	if err != nil {
		t.Fatalf("NewConfiguredPktProc failed: %v", err)
	}
	dec, err := NewConfiguredPktDecode(0, config)
	if err != nil {
		t.Fatalf("NewConfiguredPktDecode failed: %v", err)
	}

	_, err = proc.TraceDataIn(ocsd.OpFlush, 0, nil)
	resp := ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response on proc flush, got %v", resp)
	}
	_, err = proc.TraceDataIn(ocsd.OpReset, 0, nil)
	resp = ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response on proc reset, got %v", resp)
	}

	resp = ocsd.DataRespFromErr(dec.PacketDataIn(ocsd.OpFlush, 0, nil))
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response on decoder flush, got %v", resp)
	}
	resp = ocsd.DataRespFromErr(dec.PacketDataIn(ocsd.OpReset, 0, nil))
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal response on decoder reset, got %v", resp)
	}

	pkt := &Packet{}
	pkt.ResetNextPacket()
	pkt.SetPacketType(PktD8, false)
	pkt.OrigType = pkt.Type
	pkt.Type = PktBadSequence
	if !pkt.IsBadPacket() {
		t.Errorf("Expected IsBadPacket to be true")
	}
}

func TestSTMTypedConstructors(t *testing.T) {
	t.Run("ConfiguredPktProc", func(t *testing.T) {
		cfg := NewConfig()
		cfg.SetTraceID(0x31)

		proc, err := NewConfiguredPktProc(1, cfg)
		if err != nil {
			t.Fatalf("NewConfiguredPktProc failed: %v", err)
		}
		if proc == nil || proc.Config != cfg {
			t.Fatal("expected typed processor constructor to retain config")
		}
	})

	t.Run("ConfiguredPktDecode", func(t *testing.T) {
		cfg := NewConfig()
		cfg.SetTraceID(0x32)

		dec, err := NewConfiguredPktDecode(2, cfg)
		if err != nil {
			t.Fatalf("NewConfiguredPktDecode failed: %v", err)
		}
		if dec == nil || dec.Config != cfg {
			t.Fatal("expected typed decoder constructor to retain config")
		}
	})

	t.Run("RejectNilConfig", func(t *testing.T) {
		if proc, err := NewConfiguredPktProc(0, nil); proc != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
			t.Fatalf("expected nil-config proc constructor to fail, got proc=%v err=%v", proc, err)
		}
		if dec, err := NewConfiguredPktDecode(0, nil); dec != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
			t.Fatalf("expected nil-config decode constructor to fail, got dec=%v err=%v", dec, err)
		}
		if proc, dec, err := NewConfiguredPipeline(0, nil); proc != nil || dec != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
			t.Fatalf("expected nil-config pipeline constructor to fail, got proc=%v dec=%v err=%v", proc, dec, err)
		}
	})
}

func isErrorCode(err error, code error) bool {
	return errors.Is(err, code)
}

type dummyMon struct{}

func (d *dummyMon) RawPacketDataMon(op ocsd.DatapathOp, index ocsd.TrcIndex, pkt fmt.Stringer, data []byte) {
}

func TestWaitForSync_WrapAround(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("waitForSync panicked: %v", r)
		}
	}()
	proc := &PktProc{}
	proc.PktRawMonI = &dummyMon{}
	proc.numNibbles = 5
	proc.numFNibbles = 6
	proc.dataInSize = 10
	proc.dataIn = make([]byte, 10)
	proc.waitForSync(0)
}

func TestDecodeNextPacketNullSTM(t *testing.T) {
	// lower nibble 0x0 = NULL opcode
	data := []byte{0x00}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Errorf("consumed: got %d, want 1", consumed)
	}
	if pkt.Type != PktNull {
		t.Errorf("Type: got %v, want PktNull", pkt.Type)
	}
}

func TestDecodeNextPacketNullSTMAtNibbleOffset1(t *testing.T) {
	// byte 0x0F: lower nibble=0xF (FExt, unused here), upper nibble=0x0 (NULL)
	// Starting at nibble offset 1 should decode the NULL in the upper half.
	data := []byte{0x0F}
	pkt, consumed, err := decodeNextPacket(data, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Errorf("consumed: got %d, want 1", consumed)
	}
	if pkt.Type != PktNull {
		t.Errorf("Type: got %v, want PktNull", pkt.Type)
	}
}

func TestDecodeNextPacketFlagSTM(t *testing.T) {
	// byte 0xEF: lower nibble=0xF (FExt), upper nibble=0xE (op2N Flag)
	data := []byte{0xEF}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Errorf("consumed: got %d, want 2", consumed)
	}
	if pkt.Type != PktFlag {
		t.Errorf("Type: got %v, want PktFlag", pkt.Type)
	}
}

func TestDecodeNextPacketReturnsSentinelForUnmigratedHeaderSTM(t *testing.T) {
	// lower nibble 0x2 = MERR opcode, not yet migrated
	data := []byte{0x02}
	_, _, err := decodeNextPacket(data, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Errorf("expected errDecodeNotImplemented, got %v", err)
	}
}

func TestDecodeNextPacketM8STM(t *testing.T) {
	// Nibble stream: 1 A B => M8 with master 0xAB.
	data := []byte{0xA1, 0x0B}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 nibbles consumed, got %d", consumed)
	}
	if pkt.Type != PktM8 {
		t.Fatalf("expected PktM8, got %v", pkt.Type)
	}
	if pkt.Master != 0xAB {
		t.Fatalf("expected master 0xAB, got 0x%X", pkt.Master)
	}
}

func TestDecodeNextPacketC8STM(t *testing.T) {
	// Nibble stream: 3 1 2 => C8 with channel 0x12.
	data := []byte{0x13, 0x02}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 nibbles consumed, got %d", consumed)
	}
	if pkt.Type != PktC8 {
		t.Fatalf("expected PktC8, got %v", pkt.Type)
	}
	if pkt.Channel != 0x12 {
		t.Fatalf("expected channel 0x12, got 0x%X", pkt.Channel)
	}
}

func TestDecodeNextPacketD4STM(t *testing.T) {
	// Nibble stream: C 5 => D4 payload 0x5.
	data := []byte{0x5C}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 nibbles consumed, got %d", consumed)
	}
	if pkt.Type != PktD4 {
		t.Fatalf("expected PktD4, got %v", pkt.Type)
	}
	if pkt.Payload.D8 != 0x5 {
		t.Fatalf("expected payload 0x5, got 0x%X", pkt.Payload.D8)
	}
}

func TestDecodeNextPacketM8IncompleteFallsBackSTM(t *testing.T) {
	data := []byte{0x01}
	_, _, err := decodeNextPacket(data, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Errorf("expected errDecodeNotImplemented, got %v", err)
	}
}
