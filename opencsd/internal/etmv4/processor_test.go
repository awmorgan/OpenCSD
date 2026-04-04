package etmv4

import (
	"errors"
	"testing"

	"opencsd/internal/ocsd"
)

type capturePktOut struct {
	count int
	last  TracePacket
}

func (c *capturePktOut) TracePacketData(_ ocsd.TrcIndex, pkt *TracePacket) error {
	c.count++
	if pkt != nil {
		c.last = *pkt
	}
	return nil
}

func (c *capturePktOut) TracePacketEOT() error { return nil }

func (c *capturePktOut) TracePacketFlush() error { return nil }

func (c *capturePktOut) TracePacketReset(_ ocsd.TrcIndex) error { return nil }

func TestProcessorResetPacketStateClearsConditionalState(t *testing.T) {
	p := NewProcessor(&Config{})
	p.currPacketData = []byte{0xAA, 0xBB}
	p.currPacket.CondInstr = CondInstr{
		CondCKey:   0x23,
		NumCElem:   4,
		CondKeySet: true,
	}
	p.currPacket.CondResult = CondResult{
		CondRKey0:  0x12,
		CondRKey1:  0x34,
		Res0:       0xA,
		Res1:       0x5,
		KeyRes0Set: true,
		KeyRes1Set: true,
	}

	p.resetPacketState()

	if len(p.currPacketData) != 0 {
		t.Fatalf("expected packet data cleared, got %d bytes", len(p.currPacketData))
	}
	if p.currPacket.CondInstr.CondKeySet {
		t.Fatalf("expected CondInstr.CondKeySet to be cleared")
	}
	if p.currPacket.CondResult.KeyRes0Set {
		t.Fatalf("expected CondResult.KeyRes0Set to be cleared")
	}
	if p.currPacket.CondResult.KeyRes1Set {
		t.Fatalf("expected CondResult.KeyRes1Set to be cleared")
	}
	if p.currPacket.CondInstr.CondCKey != 0 || p.currPacket.CondResult.CondRKey0 != 0 || p.currPacket.CondResult.CondRKey1 != 0 {
		t.Fatalf("expected conditional packet data to be reset")
	}
}

func TestProcessorIAtomF6MatchesReferencePattern(t *testing.T) {
	p := NewProcessor(&Config{})
	p.currPacket.Type = PktAtomF6

	p.iAtom(0x00)

	if p.currPacket.Atom.Num != 4 {
		t.Fatalf("expected 4 atoms, got %d", p.currPacket.Atom.Num)
	}
	if got := p.currPacket.Atom.EnBits & 0xF; got != 0xF {
		t.Fatalf("expected low atom bits 0xF for EEEE pattern, got 0x%X", got)
	}

	p.currPacket.Type = PktAtomF6
	p.iAtom(0x20)

	if got := p.currPacket.Atom.EnBits & 0xF; got != 0x7 {
		t.Fatalf("expected low atom bits 0x7 for EEEN pattern, got 0x%X", got)
	}
}

func TestProcessorExtractCondResultMasksResultNibble(t *testing.T) {
	p := NewProcessor(&Config{})
	buf := []byte{0xDA, 0x01}

	key, result, consumed := p.extractCondResult(buf, 0)

	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if result != 0xA {
		t.Fatalf("expected result nibble 0xA, got 0x%X", result)
	}
	if key != 0xD {
		t.Fatalf("expected conditional key 0xD, got 0x%X", key)
	}
}

func TestDecodeNextPacketAtomF1(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xF7}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktAtomF1 {
		t.Fatalf("expected PktAtomF1, got %v", pkt.Type)
	}
	if pkt.Atom.Num != 1 || pkt.Atom.EnBits != 0x1 {
		t.Fatalf("unexpected atom decode: %+v", pkt.Atom)
	}
}

func TestDecodeNextPacketAtomF6(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xC0}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktAtomF6 {
		t.Fatalf("expected PktAtomF6, got %v", pkt.Type)
	}
	if pkt.Atom.Num != 4 {
		t.Fatalf("expected 4 atoms, got %d", pkt.Atom.Num)
	}
	if got := pkt.Atom.EnBits & 0xF; got != 0xF {
		t.Fatalf("expected low atom bits 0xF, got 0x%X", got)
	}
}

func TestDecodeNextPacketReturnsSentinelForUnmigratedHeader(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x01}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented, got %v", err)
	}
}

func TestDecodeNextPacketReservedHeader(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x08}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktReserved {
		t.Fatalf("expected PktReserved, got %v", pkt.Type)
	}
	if !errors.Is(pkt.Err, errReservedHeader) {
		t.Fatalf("expected errReservedHeader, got %v", pkt.Err)
	}
	if pkt.ErrHdrVal != 0x08 {
		t.Fatalf("expected header value 0x08, got 0x%X", pkt.ErrHdrVal)
	}
}

func TestDecodeNextPacketExceptionTwoByte(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x06, 0x2A}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktExcept {
		t.Fatalf("expected PktExcept, got %v", pkt.Type)
	}
	if pkt.ExceptionInfo.ExceptionType != 0x15 {
		t.Fatalf("expected exception type 0x15, got 0x%X", pkt.ExceptionInfo.ExceptionType)
	}
	if pkt.ExceptionInfo.AddrInterp != 0 {
		t.Fatalf("expected addr interp 0, got %d", pkt.ExceptionInfo.AddrInterp)
	}
	if pkt.ExceptionInfo.MFaultPending {
		t.Fatalf("did not expect MFaultPending for 2-byte exception")
	}
}

func TestDecodeNextPacketExceptionThreeByte(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x06, 0x83, 0x25}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktExcept {
		t.Fatalf("expected PktExcept, got %v", pkt.Type)
	}
	if pkt.ExceptionInfo.ExceptionType != 0xA1 {
		t.Fatalf("expected exception type 0xA1, got 0x%X", pkt.ExceptionInfo.ExceptionType)
	}
	if !pkt.ExceptionInfo.MFaultPending {
		t.Fatalf("expected MFaultPending for 3-byte exception")
	}
}

func TestDecodeNextPacketExceptionAmbiguousEteSizedFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x06, 0x00}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for ambiguous ETE exception, got %v", err)
	}
}

func TestDecodeNextPacketTimestampNoCycleCount(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x02, 0x2A}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktTimestamp {
		t.Fatalf("expected PktTimestamp, got %v", pkt.Type)
	}
	if !pkt.Valid.Timestamp {
		t.Fatalf("expected timestamp valid flag")
	}
	if pkt.Timestamp != 0x2A {
		t.Fatalf("expected timestamp 0x2A, got 0x%X", pkt.Timestamp)
	}
	if pkt.Valid.CycleCount {
		t.Fatalf("did not expect cycle count for 0x02 header")
	}
}

func TestDecodeNextPacketTimestampWithCycleCount(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x03, 0x01, 0x05}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktTimestamp {
		t.Fatalf("expected PktTimestamp, got %v", pkt.Type)
	}
	if pkt.Timestamp != 0x1 {
		t.Fatalf("expected timestamp 0x1, got 0x%X", pkt.Timestamp)
	}
	if !pkt.Valid.CycleCount || pkt.CycleCount != 0x5 {
		t.Fatalf("expected cycle count 0x5 with valid flag, got count=0x%X valid=%v", pkt.CycleCount, pkt.Valid.CycleCount)
	}
}

func TestDecodeNextPacketTimestampIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x02}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete timestamp, got %v", err)
	}
}

func TestDecodeNextPacketCycleCntF3(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x1B}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktCcntF3 {
		t.Fatalf("expected PktCcntF3, got %v", pkt.Type)
	}
	if pkt.CommitElements != 3 || pkt.CycleCount != 3 {
		t.Fatalf("unexpected F3 decode values: commit=%d cycle=%d", pkt.CommitElements, pkt.CycleCount)
	}
}

func TestDecodeNextPacketCycleCntF2(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x0C, 0xA5}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktCcntF2 {
		t.Fatalf("expected PktCcntF2, got %v", pkt.Type)
	}
	if pkt.CycleCount != 0x5 {
		t.Fatalf("expected low-nibble cycle count 0x5, got 0x%X", pkt.CycleCount)
	}
}

func TestDecodeNextPacketCycleCntF2IncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x0C}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete F2 packet, got %v", err)
	}
}

func TestDecodeNextPacketCycleCntF1WithCount(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x0E, 0x05}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktCcntF1 {
		t.Fatalf("expected PktCcntF1, got %v", pkt.Type)
	}
	if !pkt.Valid.CycleCount || pkt.CycleCount != 0x5 {
		t.Fatalf("unexpected F1 cycle count decode: valid=%v count=%d", pkt.Valid.CycleCount, pkt.CycleCount)
	}
}

func TestDecodeNextPacketCycleCntF1NoCount(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x0F}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktCcntF1 {
		t.Fatalf("expected PktCcntF1, got %v", pkt.Type)
	}
	if pkt.Valid.CycleCount || pkt.CycleCount != 0 {
		t.Fatalf("unexpected F1 no-count decode: valid=%v count=%d", pkt.Valid.CycleCount, pkt.CycleCount)
	}
}

func TestDecodeNextPacketCycleCntF1IncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x0E}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete F1 packet, got %v", err)
	}
}

func TestProcessDataFastPathCycleCntF3CommitOpt0(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	p.currPacket.CCThreshold = 10
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x1B})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if out.count != 1 {
		t.Fatalf("expected one output packet, got %d", out.count)
	}
	if out.last.Type != PktCcntF3 {
		t.Fatalf("expected output type PktCcntF3, got %v", out.last.Type)
	}
	if out.last.CycleCount != 13 {
		t.Fatalf("expected cycle count 13, got %d", out.last.CycleCount)
	}
	if !out.last.Valid.CommitElem || out.last.CommitElements != 3 {
		t.Fatalf("unexpected commit elem decode: valid=%v value=%d", out.last.Valid.CommitElem, out.last.CommitElements)
	}
	if out.last.Valid.CCExactMatch {
		t.Fatalf("did not expect CCExactMatch for threshold 10 and count 13")
	}
}

func TestProcessDataFastPathCycleCntF3CommitOpt1(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: (1 << 29) | (1 << 7)})
	p.isSync = true
	p.currPacket.CCThreshold = 5
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if out.count != 1 {
		t.Fatalf("expected one output packet, got %d", out.count)
	}
	if out.last.CycleCount != 5 || !out.last.Valid.CCExactMatch {
		t.Fatalf("expected exact CC match at threshold, got count=%d exact=%v", out.last.CycleCount, out.last.Valid.CCExactMatch)
	}
	if out.last.Valid.CommitElem {
		t.Fatalf("did not expect commit elements when CommitOpt1 is enabled")
	}
}

func TestProcessDataFastPathCycleCntF2CommitOpt1(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: (1 << 29) | (1 << 7)})
	p.isSync = true
	p.currPacket.CCThreshold = 9
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x0C, 0xA5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if out.count != 1 || out.last.Type != PktCcntF2 {
		t.Fatalf("unexpected output packet: count=%d type=%v", out.count, out.last.Type)
	}
	if out.last.CycleCount != 14 {
		t.Fatalf("expected cycle count 14, got %d", out.last.CycleCount)
	}
	if out.last.Valid.CCExactMatch {
		t.Fatalf("did not expect CCExactMatch for threshold 9 and count 14")
	}
}

func TestProcessDataCycleCntF2FallsBackWhenCommitOpt1Off(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	p.currPacket.CCThreshold = 0
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x0C, 0xA5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if out.count != 1 || out.last.Type != PktCcntF2 {
		t.Fatalf("unexpected output packet: count=%d type=%v", out.count, out.last.Type)
	}
	// Legacy path should be used here and include commit elements.
	if !out.last.Valid.CommitElem {
		t.Fatalf("expected commit elements from legacy F2 path when CommitOpt1 is off")
	}
}

func TestProcessDataFastPathCycleCntF1CommitOpt1WithCount(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: (1 << 29) | (1 << 7)})
	p.isSync = true
	p.currPacket.CCThreshold = 7
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x0E, 0x02})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if out.count != 1 || out.last.Type != PktCcntF1 {
		t.Fatalf("unexpected output packet: count=%d type=%v", out.count, out.last.Type)
	}
	if out.last.CycleCount != 9 {
		t.Fatalf("expected cycle count 9, got %d", out.last.CycleCount)
	}
	if out.last.Valid.CCExactMatch {
		t.Fatalf("did not expect CCExactMatch for threshold 7 and count 9")
	}
}

func TestProcessDataFastPathCycleCntF1CommitOpt1NoCount(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: (1 << 29) | (1 << 7)})
	p.isSync = true
	p.currPacket.CCThreshold = 7
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x0F})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if out.count != 1 || out.last.Type != PktCcntF1 {
		t.Fatalf("unexpected output packet: count=%d type=%v", out.count, out.last.Type)
	}
	if out.last.CycleCount != 0 || out.last.Valid.CCExactMatch {
		t.Fatalf("expected zero cycle and no exact match for no-count F1, got count=%d exact=%v", out.last.CycleCount, out.last.Valid.CCExactMatch)
	}
}

func TestProcessDataCycleCntF1FallsBackWhenCommitOpt1Off(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	p.currPacket.CCThreshold = 0
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x0E, 0x02, 0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", consumed)
	}
	if out.count != 1 || out.last.Type != PktCcntF1 {
		t.Fatalf("unexpected output packet: count=%d type=%v", out.count, out.last.Type)
	}
	if !out.last.Valid.CommitElem {
		t.Fatalf("expected commit elements from legacy F1 path when CommitOpt1 is off")
	}
}

func TestDecodeNextPacketSpecResSimplePackets(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x31}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || pkt.Type != PktMispredict {
		t.Fatalf("unexpected mispredict decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.Atom.Num != 1 || pkt.Atom.EnBits != 0x1 || pkt.CancelElements != 0 {
		t.Fatalf("unexpected mispredict payload: atom=%+v cancel=%d", pkt.Atom, pkt.CancelElements)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x36}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || pkt.Type != PktCancelF2 {
		t.Fatalf("unexpected cancelF2 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.Atom.Num != 2 || pkt.Atom.EnBits != 0x3 || pkt.CancelElements != 1 {
		t.Fatalf("unexpected cancelF2 payload: atom=%+v cancel=%d", pkt.Atom, pkt.CancelElements)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x3D}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || pkt.Type != PktCancelF3 {
		t.Fatalf("unexpected cancelF3 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.Atom.Num != 1 || pkt.Atom.EnBits != 0x1 || pkt.CancelElements != 4 {
		t.Fatalf("unexpected cancelF3 payload: atom=%+v cancel=%d", pkt.Atom, pkt.CancelElements)
	}
}

func TestProcessDataFastPathSpecResSimplePacket(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x3D})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if out.count != 1 || out.last.Type != PktCancelF3 {
		t.Fatalf("unexpected output packet: count=%d type=%v", out.count, out.last.Type)
	}
	if out.last.Atom.Num != 1 || out.last.Atom.EnBits != 0x1 || out.last.CancelElements != 4 {
		t.Fatalf("unexpected output payload: atom=%+v cancel=%d", out.last.Atom, out.last.CancelElements)
	}
}

func TestDecodeNextPacketSpecResVariablePackets(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x2D, 0x07}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || pkt.Type != PktCommit || pkt.CommitElements != 7 {
		t.Fatalf("unexpected commit decode: consumed=%d type=%v commit=%d", consumed, pkt.Type, pkt.CommitElements)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x2E, 0x03}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || pkt.Type != PktCancelF1 || pkt.CancelElements != 3 {
		t.Fatalf("unexpected cancelF1 decode: consumed=%d type=%v cancel=%d", consumed, pkt.Type, pkt.CancelElements)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x2F, 0x05}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || pkt.Type != PktCancelF1Mispred || pkt.CancelElements != 5 {
		t.Fatalf("unexpected cancelF1 mispred decode: consumed=%d type=%v cancel=%d", consumed, pkt.Type, pkt.CancelElements)
	}
}

func TestDecodeNextPacketSpecResVariableIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x2D}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete commit packet, got %v", err)
	}
}

func TestDecodeNextPacketCondIF2(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x42}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || pkt.Type != PktCondIF2 {
		t.Fatalf("unexpected CondIF2 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.CondInstr.CondCKey != 0x2 {
		t.Fatalf("expected CondCKey 2, got %d", pkt.CondInstr.CondCKey)
	}
}

func TestDecodeNextPacketCondResF3(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x5A, 0xBC}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || pkt.Type != PktCondResF3 {
		t.Fatalf("unexpected CondResF3 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.CondResult.F3Tokens != 0xABC {
		t.Fatalf("expected F3Tokens 0xABC, got 0x%X", pkt.CondResult.F3Tokens)
	}
}

func TestDecodeNextPacketCondResF3IncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x50}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete CondResF3 packet, got %v", err)
	}
}

func TestDecodeNextPacketCondIF3(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x6D, 0x07}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || pkt.Type != PktCondIF3 {
		t.Fatalf("unexpected CondIF3 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.CondInstr.NumCElem != 4 || !pkt.CondInstr.F3FinalElem {
		t.Fatalf("unexpected CondIF3 payload: num=%d final=%v", pkt.CondInstr.NumCElem, pkt.CondInstr.F3FinalElem)
	}
}

func TestDecodeNextPacketCondResF2AndF4(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x4E}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || pkt.Type != PktCondResF2 {
		t.Fatalf("unexpected CondResF2 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.CondResult.F2KeyIncr != 2 || pkt.CondResult.Res0 != 0x2 {
		t.Fatalf("unexpected CondResF2 payload: incr=%d res=%d", pkt.CondResult.F2KeyIncr, pkt.CondResult.Res0)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x46}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || pkt.Type != PktCondResF4 {
		t.Fatalf("unexpected CondResF4 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if pkt.CondResult.Res0 != 0x2 {
		t.Fatalf("unexpected CondResF4 payload: res=%d", pkt.CondResult.Res0)
	}
}

func TestDecodeNextPacketCondIF1(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x6C, 0x8A, 0x01}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 || pkt.Type != PktCondIF1 {
		t.Fatalf("unexpected CondIF1 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if !pkt.CondInstr.CondKeySet || pkt.CondInstr.CondCKey != 0x8A {
		t.Fatalf("unexpected CondIF1 payload: keySet=%v key=%d", pkt.CondInstr.CondKeySet, pkt.CondInstr.CondCKey)
	}
}

func TestDecodeNextPacketCondResF1(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x68, 0x5A, 0x34}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 || pkt.Type != PktCondResF1 {
		t.Fatalf("unexpected CondResF1 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if !pkt.CondResult.KeyRes0Set || !pkt.CondResult.KeyRes1Set {
		t.Fatalf("expected both key/result pairs set: %+v", pkt.CondResult)
	}
	if pkt.CondResult.CondRKey0 != 0x5 || pkt.CondResult.Res0 != 0xA {
		t.Fatalf("unexpected first key/result: key=%d res=%d", pkt.CondResult.CondRKey0, pkt.CondResult.Res0)
	}
	if pkt.CondResult.CondRKey1 != 0x3 || pkt.CondResult.Res1 != 0x4 {
		t.Fatalf("unexpected second key/result: key=%d res=%d", pkt.CondResult.CondRKey1, pkt.CondResult.Res1)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x6E, 0xDA, 0x01}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 || pkt.Type != PktCondResF1 {
		t.Fatalf("unexpected single-part CondResF1 decode: consumed=%d type=%v", consumed, pkt.Type)
	}
	if !pkt.CondResult.KeyRes0Set || pkt.CondResult.KeyRes1Set {
		t.Fatalf("expected only first key/result set: %+v", pkt.CondResult)
	}
}

func TestDecodeNextPacketCondResF1IncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x68, 0x5A}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete CondResF1 packet, got %v", err)
	}
}

func TestProcessDataFastPathSpecResVariablePackets(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x2D, 0x07})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || out.count != 1 || out.last.Type != PktCommit {
		t.Fatalf("unexpected commit output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if out.last.CommitElements != 7 {
		t.Fatalf("expected commit elements 7, got %d", out.last.CommitElements)
	}

	consumed, err = p.processData(2, []byte{0x2F, 0x05})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || out.count != 2 || out.last.Type != PktCancelF1Mispred {
		t.Fatalf("unexpected cancel output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if out.last.CancelElements != 5 {
		t.Fatalf("expected cancel elements 5, got %d", out.last.CancelElements)
	}
}

func TestProcessDataFastPathConditionalPackets(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: 0x40, RegConfigr: 1 << 8})
	p.isSync = true
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || out.count != 1 || out.last.Type != PktCondIF2 {
		t.Fatalf("unexpected CondIF2 output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if out.last.CondInstr.CondCKey != 0x2 {
		t.Fatalf("expected CondCKey 2, got %d", out.last.CondInstr.CondCKey)
	}

	consumed, err = p.processData(1, []byte{0x5A, 0xBC})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || out.count != 2 || out.last.Type != PktCondResF3 {
		t.Fatalf("unexpected CondResF3 output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if out.last.CondResult.F3Tokens != 0xABC {
		t.Fatalf("expected F3Tokens 0xABC, got 0x%X", out.last.CondResult.F3Tokens)
	}

	consumed, err = p.processData(3, []byte{0x6D, 0x07})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 || out.count != 3 || out.last.Type != PktCondIF3 {
		t.Fatalf("unexpected CondIF3 output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if out.last.CondInstr.NumCElem != 4 || !out.last.CondInstr.F3FinalElem {
		t.Fatalf("unexpected CondIF3 output payload: num=%d final=%v", out.last.CondInstr.NumCElem, out.last.CondInstr.F3FinalElem)
	}

	consumed, err = p.processData(5, []byte{0x4E})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || out.count != 4 || out.last.Type != PktCondResF2 {
		t.Fatalf("unexpected CondResF2 output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if out.last.CondResult.F2KeyIncr != 2 || out.last.CondResult.Res0 != 0x2 {
		t.Fatalf("unexpected CondResF2 output payload: incr=%d res=%d", out.last.CondResult.F2KeyIncr, out.last.CondResult.Res0)
	}

	consumed, err = p.processData(6, []byte{0x46})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || out.count != 5 || out.last.Type != PktCondResF4 {
		t.Fatalf("unexpected CondResF4 output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if out.last.CondResult.Res0 != 0x2 {
		t.Fatalf("unexpected CondResF4 output payload: res=%d", out.last.CondResult.Res0)
	}

	consumed, err = p.processData(7, []byte{0x6C, 0x8A, 0x01})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 || out.count != 6 || out.last.Type != PktCondIF1 {
		t.Fatalf("unexpected CondIF1 output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if !out.last.CondInstr.CondKeySet || out.last.CondInstr.CondCKey != 0x8A {
		t.Fatalf("unexpected CondIF1 output payload: keySet=%v key=%d", out.last.CondInstr.CondKeySet, out.last.CondInstr.CondCKey)
	}

	consumed, err = p.processData(10, []byte{0x68, 0x5A, 0x34})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 || out.count != 7 || out.last.Type != PktCondResF1 {
		t.Fatalf("unexpected CondResF1 output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if !out.last.CondResult.KeyRes0Set || !out.last.CondResult.KeyRes1Set {
		t.Fatalf("expected CondResF1 output key/result pairs set: %+v", out.last.CondResult)
	}
}

func TestProcessDataConditionalPacketsFallbackWhenCondTraceDisabled(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || out.count != 1 || out.last.Type != PktCondIF2 {
		t.Fatalf("unexpected CondIF2 fallback output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if !errors.Is(out.last.Err, errReservedCfg) {
		t.Fatalf("expected reserved-cfg error for CondIF2 fallback, got %v", out.last.Err)
	}

	consumed, err = p.processData(1, []byte{0x6C})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 || out.count != 2 || out.last.Type != PktCondIF1 {
		t.Fatalf("unexpected CondIF1 fallback output: consumed=%d count=%d type=%v", consumed, out.count, out.last.Type)
	}
	if !errors.Is(out.last.Err, errReservedCfg) {
		t.Fatalf("expected reserved-cfg error for CondIF1 fallback, got %v", out.last.Err)
	}
}

func TestProcessDataFastPathInvalidCfgHeaderConsumesOneByte(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if out.count != 1 {
		t.Fatalf("expected one output packet, got %d", out.count)
	}
	if out.last.Type != PktCondIF2 {
		t.Fatalf("expected PktCondIF2 output, got %v", out.last.Type)
	}
	if !errors.Is(out.last.Err, errReservedCfg) {
		t.Fatalf("expected errReservedCfg output, got %v", out.last.Err)
	}
	if out.last.ErrHdrVal != 0x42 {
		t.Fatalf("expected header value 0x42, got 0x%X", out.last.ErrHdrVal)
	}
}

func TestProcessDataFastPathReservedHeader(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x08})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if out.count != 1 {
		t.Fatalf("expected one output packet, got %d", out.count)
	}
	if out.last.Type != PktReserved {
		t.Fatalf("expected PktReserved output, got %v", out.last.Type)
	}
	if !errors.Is(out.last.Err, errReservedHeader) {
		t.Fatalf("expected errReservedHeader output, got %v", out.last.Err)
	}
	if out.last.ErrHdrVal != 0x08 {
		t.Fatalf("expected output header value 0x08, got 0x%X", out.last.ErrHdrVal)
	}
}

func TestDecodeNextPacketTraceOn(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x04}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktTraceOn {
		t.Fatalf("expected PktTraceOn, got %v", pkt.Type)
	}
}

func TestDecodeNextPacketFuncRet(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x05}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktFuncRet {
		t.Fatalf("expected PktFuncRet, got %v", pkt.Type)
	}
}

func TestDecodeNextPacketExceptRtn(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x07}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktExceptRtn {
		t.Fatalf("expected PktExceptRtn, got %v", pkt.Type)
	}
}

func TestDecodeNextPacketEteTransPackets(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x0A}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktTransSt {
		t.Fatalf("expected ETE_PktTransSt, got %v", pkt.Type)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x0B}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktTransCommit {
		t.Fatalf("expected ETE_PktTransCommit, got %v", pkt.Type)
	}
}

func TestDecodeNextPacketIgnoreAndTsMarker(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x70}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktIgnore {
		t.Fatalf("expected PktIgnore, got %v", pkt.Type)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x88}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktTSMarker {
		t.Fatalf("expected ETE_PktTSMarker, got %v", pkt.Type)
	}
}

func TestDecodeNextPacketEvent(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x7D}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktEvent {
		t.Fatalf("expected PktEvent, got %v", pkt.Type)
	}
	if pkt.EventVal != 0xD {
		t.Fatalf("expected event value 0xD, got 0x%X", pkt.EventVal)
	}
}

func TestDecodeNextPacketAddrMatch(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x91}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrMatch {
		t.Fatalf("expected PktAddrMatch, got %v", pkt.Type)
	}
	if pkt.AddrExactMatchIdx != 0x1 {
		t.Fatalf("expected address match idx 1, got %d", pkt.AddrExactMatchIdx)
	}
	if !pkt.Valid.ExactMatchIdxValid {
		t.Fatalf("expected exact-match valid flag set")
	}
}

func TestDecodeNextPacketEteSrcAddrMatch(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xB2}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktSrcAddrMatch {
		t.Fatalf("expected ETE_PktSrcAddrMatch, got %v", pkt.Type)
	}
	if pkt.AddrExactMatchIdx != 0x2 {
		t.Fatalf("expected source address match idx 2, got %d", pkt.AddrExactMatchIdx)
	}
	if !pkt.Valid.ExactMatchIdxValid {
		t.Fatalf("expected exact-match valid flag set")
	}
}

func TestDecodeNextPacketTraceInfoInfoOnly(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x01, 0x01, 0x43}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktTraceInfo {
		t.Fatalf("expected PktTraceInfo, got %v", pkt.Type)
	}
	if !pkt.Valid.TInfo {
		t.Fatalf("expected trace info valid flag")
	}
	if pkt.TraceInfo.Val != 0x43 {
		t.Fatalf("expected trace info value 0x43, got 0x%X", pkt.TraceInfo.Val)
	}
	if !pkt.TraceInfo.CCEnabled {
		t.Fatalf("expected CCEnabled set")
	}
	if pkt.TraceInfo.CondEnabled != 1 {
		t.Fatalf("expected CondEnabled=1, got %d", pkt.TraceInfo.CondEnabled)
	}
	if !pkt.TraceInfo.InTransState {
		t.Fatalf("expected InTransState set")
	}
}

func TestDecodeNextPacketTraceInfoMultipleSections(t *testing.T) {
	data := []byte{0x01, 0x0F, 0x01, 0x02, 0x03, 0x04}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != len(data) {
		t.Fatalf("expected %d bytes consumed, got %d", len(data), consumed)
	}
	if pkt.Type != PktTraceInfo {
		t.Fatalf("expected PktTraceInfo, got %v", pkt.Type)
	}
	if pkt.TraceInfo.Val != 0x1 {
		t.Fatalf("expected info value 0x1, got 0x%X", pkt.TraceInfo.Val)
	}
	if pkt.P0Key != 0x2 {
		t.Fatalf("expected P0Key 0x2, got 0x%X", pkt.P0Key)
	}
	if pkt.CurrSpecDepth != 0x3 || !pkt.Valid.SpecDepthValid || !pkt.TraceInfo.SpecFieldPresent {
		t.Fatalf("unexpected spec section decode: depth=0x%X valid=%v present=%v", pkt.CurrSpecDepth, pkt.Valid.SpecDepthValid, pkt.TraceInfo.SpecFieldPresent)
	}
	if pkt.CCThreshold != 0x4 || !pkt.Valid.CCThreshold {
		t.Fatalf("unexpected cycle threshold decode: threshold=0x%X valid=%v", pkt.CCThreshold, pkt.Valid.CCThreshold)
	}
}

func TestDecodeNextPacketTraceInfoIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x01, 0x01}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete trace info, got %v", err)
	}
}

func TestDecodeNextPacketLongAddr64IS0(t *testing.T) {
	data := []byte{0x9D, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 9 {
		t.Fatalf("expected 9 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrL_64IS0 {
		t.Fatalf("expected PktAddrL_64IS0, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x10 {
		t.Fatalf("expected address 0x10, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrValidBits != 64 || pkt.VAddrPktBits != 64 || pkt.VAddrISA != 0 {
		t.Fatalf("unexpected address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketLongAddr64IS1(t *testing.T) {
	data := []byte{0x9E, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 9 {
		t.Fatalf("expected 9 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrL_64IS1 {
		t.Fatalf("expected PktAddrL_64IS1, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x4 {
		t.Fatalf("expected address 0x4, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrValidBits != 64 || pkt.VAddrPktBits != 64 || pkt.VAddrISA != 1 {
		t.Fatalf("unexpected address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketEteSrcLongAddr64IS0(t *testing.T) {
	data := []byte{0xB8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 9 {
		t.Fatalf("expected 9 bytes consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktSrcAddrL_64IS0 {
		t.Fatalf("expected ETE_PktSrcAddrL_64IS0, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x10 {
		t.Fatalf("expected address 0x10, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrValidBits != 64 || pkt.VAddrPktBits != 64 || pkt.VAddrISA != 0 {
		t.Fatalf("unexpected address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketLongAddr32IS0(t *testing.T) {
	data := []byte{0x9A, 0x04, 0x00, 0x34, 0x12}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 5 {
		t.Fatalf("expected 5 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrL_32IS0 {
		t.Fatalf("expected PktAddrL_32IS0, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x12340010 {
		t.Fatalf("expected address 0x12340010, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrValidBits != 32 || pkt.VAddrPktBits != 32 || pkt.VAddrISA != 0 {
		t.Fatalf("unexpected address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketLongAddr32IS1(t *testing.T) {
	data := []byte{0x9B, 0x02, 0x01, 0x34, 0x12}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 5 {
		t.Fatalf("expected 5 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrL_32IS1 {
		t.Fatalf("expected PktAddrL_32IS1, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x12340104 {
		t.Fatalf("expected address 0x12340104, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrValidBits != 32 || pkt.VAddrPktBits != 32 || pkt.VAddrISA != 1 {
		t.Fatalf("unexpected address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketAddrContext32NoIDs(t *testing.T) {
	data := []byte{0x82, 0x04, 0x00, 0x34, 0x12, 0x19}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 6 {
		t.Fatalf("expected 6 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrCtxtL_32IS0 {
		t.Fatalf("expected PktAddrCtxtL_32IS0, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x12340010 || pkt.VAddrPktBits != 32 || pkt.VAddrISA != 0 {
		t.Fatalf("unexpected address decode: addr=0x%X bits=%d isa=%d", pkt.VAddr, pkt.VAddrPktBits, pkt.VAddrISA)
	}
	if !pkt.Valid.Context || !pkt.Context.Updated || pkt.Context.EL != 0x1 || !pkt.Context.NSE || !pkt.Context.SF || pkt.Context.NS {
		t.Fatalf("unexpected context decode: %+v", pkt.Context)
	}
}

func TestDecodeNextPacketAddrContext64NoIDs(t *testing.T) {
	data := []byte{0x86, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 10 {
		t.Fatalf("expected 10 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrCtxtL_64IS1 {
		t.Fatalf("expected PktAddrCtxtL_64IS1, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x4 || pkt.VAddrPktBits != 64 || pkt.VAddrISA != 1 {
		t.Fatalf("unexpected address decode: addr=0x%X bits=%d isa=%d", pkt.VAddr, pkt.VAddrPktBits, pkt.VAddrISA)
	}
	if !pkt.Valid.Context || !pkt.Context.Updated || pkt.Context.EL != 0x1 {
		t.Fatalf("unexpected context decode: %+v", pkt.Context)
	}
}

func TestDecodeNextPacketAddrContextWithIDsFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x82, 0x04, 0x00, 0x34, 0x12, 0x40}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for config-sized addr+context payload, got %v", err)
	}
}

func TestDecodeNextPacketEteSrcLongAddr32IS1(t *testing.T) {
	data := []byte{0xB7, 0x02, 0x01, 0x34, 0x12}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 5 {
		t.Fatalf("expected 5 bytes consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktSrcAddrL_32IS1 {
		t.Fatalf("expected ETE_PktSrcAddrL_32IS1, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x12340104 {
		t.Fatalf("expected address 0x12340104, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrValidBits != 32 || pkt.VAddrPktBits != 32 || pkt.VAddrISA != 1 {
		t.Fatalf("unexpected address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketShortAddrIS0SingleByte(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x95, 0x15}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrS_IS0 {
		t.Fatalf("expected PktAddrS_IS0, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x54 {
		t.Fatalf("expected short address 0x54, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrPktBits != 9 || pkt.VAddrValidBits != 9 || pkt.VAddrISA != 0 {
		t.Fatalf("unexpected short address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketShortAddrIS1TwoByte(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x96, 0x81, 0x23}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAddrS_IS1 {
		t.Fatalf("expected PktAddrS_IS1, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x2302 {
		t.Fatalf("expected short address 0x2302, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrPktBits != 16 || pkt.VAddrValidBits != 16 || pkt.VAddrISA != 1 {
		t.Fatalf("unexpected short address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketEteSrcShortAddrIS1(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xB5, 0x02}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktSrcAddrS_IS1 {
		t.Fatalf("expected ETE_PktSrcAddrS_IS1, got %v", pkt.Type)
	}
	if pkt.VAddr != 0x4 {
		t.Fatalf("expected short address 0x4, got 0x%X", pkt.VAddr)
	}
	if pkt.VAddrPktBits != 8 || pkt.VAddrValidBits != 8 || pkt.VAddrISA != 1 {
		t.Fatalf("unexpected short address metadata: valid=%d pkt=%d isa=%d", pkt.VAddrValidBits, pkt.VAddrPktBits, pkt.VAddrISA)
	}
}

func TestDecodeNextPacketShortAddrIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x96, 0x80}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete short address, got %v", err)
	}
}

func TestProcessDataFastPathShortAddrMergesWithExistingAddress(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	p.currPacket.VAddr = 0xFFFF0000
	p.currPacket.VAddrValidBits = 32

	consumed, err := p.processData(0, []byte{0x95, 0x15})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if p.currPacket.VAddr != 0xFFFF0054 {
		t.Fatalf("expected merged address 0xFFFF0054, got 0x%X", p.currPacket.VAddr)
	}
	if p.currPacket.VAddrValidBits != 32 {
		t.Fatalf("expected valid bits to remain 32, got %d", p.currPacket.VAddrValidBits)
	}
	if p.currPacket.VAddrPktBits != 9 || p.currPacket.VAddrISA != 0 {
		t.Fatalf("unexpected packet metadata: pktBits=%d isa=%d", p.currPacket.VAddrPktBits, p.currPacket.VAddrISA)
	}
}

func TestProcessDataFastPathLongAddr32KeepsUpperWhenContext64Bit(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	p.currPacket.VAddr = 0x11223344AABBCCDD
	p.currPacket.VAddrValidBits = 64
	p.currPacket.Valid.Context = true
	p.currPacket.Context.SF = true

	consumed, err := p.processData(0, []byte{0x9A, 0x04, 0x00, 0x34, 0x12})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 5 {
		t.Fatalf("expected 5 bytes consumed, got %d", consumed)
	}
	if p.currPacket.VAddr != 0x1122334412340010 {
		t.Fatalf("expected merged address 0x1122334412340010, got 0x%X", p.currPacket.VAddr)
	}
	if p.currPacket.VAddrValidBits != 64 {
		t.Fatalf("expected valid bits to remain 64, got %d", p.currPacket.VAddrValidBits)
	}
	if p.currPacket.VAddrPktBits != 32 || p.currPacket.VAddrISA != 0 {
		t.Fatalf("unexpected packet metadata: pktBits=%d isa=%d", p.currPacket.VAddrPktBits, p.currPacket.VAddrISA)
	}
}

func TestProcessDataFastPathQShortAddrMergesWithExistingAddress(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: 0x1 << 15})
	p.isSync = true
	p.currPacket.VAddr = 0xFFFF0000
	p.currPacket.VAddrValidBits = 32

	consumed, err := p.processData(0, []byte{0xA5, 0x15, 0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", consumed)
	}
	if p.currPacket.VAddr != 0xFFFF0054 {
		t.Fatalf("expected merged address 0xFFFF0054, got 0x%X", p.currPacket.VAddr)
	}
	if p.currPacket.QPkt.QType != 0x5 || p.currPacket.QPkt.QCount != 0x3 {
		t.Fatalf("unexpected Q packet metadata: %+v", p.currPacket.QPkt)
	}
}

func TestProcessDataFastPathQLongAddrKeepsUpperWhenContext64Bit(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: 0x1 << 15})
	p.isSync = true
	p.currPacket.VAddr = 0x11223344AABBCCDD
	p.currPacket.VAddrValidBits = 64
	p.currPacket.Valid.Context = true
	p.currPacket.Context.SF = true

	consumed, err := p.processData(0, []byte{0xAB, 0x02, 0x01, 0x34, 0x12, 0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 6 {
		t.Fatalf("expected 6 bytes consumed, got %d", consumed)
	}
	if p.currPacket.VAddr != 0x1122334412340104 {
		t.Fatalf("expected merged address 0x1122334412340104, got 0x%X", p.currPacket.VAddr)
	}
	if p.currPacket.QPkt.QType != 0xB || p.currPacket.QPkt.QCount != 0x3 {
		t.Fatalf("unexpected Q packet metadata: %+v", p.currPacket.QPkt)
	}
}

func TestDecodeNextPacketExtensionDiscard(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x00, 0x03}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktDiscard {
		t.Fatalf("expected PktDiscard, got %v", pkt.Type)
	}
}

func TestDecodeNextPacketExtensionOverflow(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x00, 0x05}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktOverflow {
		t.Fatalf("expected PktOverflow, got %v", pkt.Type)
	}
}

func TestDecodeNextPacketExtensionAsync(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 12 {
		t.Fatalf("expected 12 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAsync {
		t.Fatalf("expected PktAsync, got %v", pkt.Type)
	}
	if pkt.Err != nil {
		t.Fatalf("expected no packet error for well-formed async, got %v", pkt.Err)
	}
}

func TestDecodeNextPacketExtensionAsyncMalformed(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 12 {
		t.Fatalf("expected 12 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktAsync {
		t.Fatalf("expected PktAsync, got %v", pkt.Type)
	}
	if !errors.Is(pkt.Err, ocsd.ErrBadPacketSeq) {
		t.Fatalf("expected ErrBadPacketSeq, got %v", pkt.Err)
	}
}

func TestDecodeNextPacketExtensionIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x00}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete extension, got %v", err)
	}
}

func TestDecodeNextPacketExtensionUnknownSubtypeProducesPacketError(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x00, 0x7A}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktExtension {
		t.Fatalf("expected PktExtension, got %v", pkt.Type)
	}
	if !errors.Is(pkt.Err, ocsd.ErrBadPacketSeq) {
		t.Fatalf("expected ErrBadPacketSeq, got %v", pkt.Err)
	}
}

func TestProcessDataFastPathExtensionUnknownSubtypeProducesPacketError(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	out := &capturePktOut{}
	p.SetPktOut(out)

	consumed, err := p.processData(0, []byte{0x00, 0x7A})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if out.count != 1 {
		t.Fatalf("expected one output packet, got %d", out.count)
	}
	if out.last.Type != PktExtension {
		t.Fatalf("expected PktExtension output, got %v", out.last.Type)
	}
	if !errors.Is(out.last.Err, ocsd.ErrBadPacketSeq) {
		t.Fatalf("expected ErrBadPacketSeq output, got %v", out.last.Err)
	}
}

func TestDecodeNextPacketITE(t *testing.T) {
	data := []byte{0x09, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pkt, consumed, err := decodeNextPacket(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 10 {
		t.Fatalf("expected 10 bytes consumed, got %d", consumed)
	}
	if pkt.Type != ETE_PktITE {
		t.Fatalf("expected ETE_PktITE, got %v", pkt.Type)
	}
	if pkt.ITEPkt.EL != 0x02 {
		t.Fatalf("expected EL 0x02, got 0x%X", pkt.ITEPkt.EL)
	}
	if pkt.ITEPkt.Value != 0x0807060504030201 {
		t.Fatalf("expected ITE value 0x0807060504030201, got 0x%X", pkt.ITEPkt.Value)
	}
}

func TestDecodeNextPacketITEIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x09, 0x02}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete ITE packet, got %v", err)
	}
}

func TestDecodeNextPacketQCountOnly(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xAC, 0x2A}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktQ {
		t.Fatalf("expected PktQ, got %v", pkt.Type)
	}
	if pkt.QPkt.QType != 0xC || !pkt.QPkt.CountPresent || pkt.QPkt.QCount != 0x2A {
		t.Fatalf("unexpected Q packet decode: %+v", pkt.QPkt)
	}
}

func TestDecodeNextPacketQAddrMatch(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xA2, 0x05}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktQ {
		t.Fatalf("expected PktQ, got %v", pkt.Type)
	}
	if pkt.QPkt.QType != 0x2 || !pkt.QPkt.AddrMatch || !pkt.QPkt.CountPresent || pkt.QPkt.QCount != 0x5 {
		t.Fatalf("unexpected Q packet decode: %+v", pkt.QPkt)
	}
	if !pkt.Valid.ExactMatchIdxValid || pkt.AddrExactMatchIdx != 0x2 {
		t.Fatalf("unexpected exact-match decode: idx=%d valid=%v", pkt.AddrExactMatchIdx, pkt.Valid.ExactMatchIdxValid)
	}
}

func TestDecodeNextPacketQShortAddrIS0WithCount(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xA5, 0x15, 0x03}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 3 {
		t.Fatalf("expected 3 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktQ {
		t.Fatalf("expected PktQ, got %v", pkt.Type)
	}
	if !pkt.Valid.VAddrValid || pkt.VAddr != 0x54 || pkt.VAddrISA != 0 || pkt.VAddrPktBits != 9 {
		t.Fatalf("unexpected Q short address decode: addr=0x%X isa=%d bits=%d valid=%v", pkt.VAddr, pkt.VAddrISA, pkt.VAddrPktBits, pkt.Valid.VAddrValid)
	}
	if pkt.QPkt.QType != 0x5 || !pkt.QPkt.AddrPresent || pkt.QPkt.AddrMatch || !pkt.QPkt.CountPresent || pkt.QPkt.QCount != 0x3 {
		t.Fatalf("unexpected Q packet decode: %+v", pkt.QPkt)
	}
}

func TestDecodeNextPacketQLongAddrIS1WithCount(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xAB, 0x02, 0x01, 0x34, 0x12, 0x03}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 6 {
		t.Fatalf("expected 6 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktQ {
		t.Fatalf("expected PktQ, got %v", pkt.Type)
	}
	if !pkt.Valid.VAddrValid || pkt.VAddr != 0x12340104 || pkt.VAddrISA != 1 || pkt.VAddrPktBits != 32 {
		t.Fatalf("unexpected Q long address decode: addr=0x%X isa=%d bits=%d valid=%v", pkt.VAddr, pkt.VAddrISA, pkt.VAddrPktBits, pkt.Valid.VAddrValid)
	}
	if pkt.QPkt.QType != 0xB || !pkt.QPkt.AddrPresent || pkt.QPkt.AddrMatch || !pkt.QPkt.CountPresent || pkt.QPkt.QCount != 0x3 {
		t.Fatalf("unexpected Q packet decode: %+v", pkt.QPkt)
	}
}

func TestDecodeNextPacketQTypeF(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0xAF}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktQ {
		t.Fatalf("expected PktQ, got %v", pkt.Type)
	}
	if pkt.QPkt.QType != 0xF {
		t.Fatalf("expected QType 0xF, got 0x%X", pkt.QPkt.QType)
	}
	if pkt.QPkt.CountPresent {
		t.Fatalf("did not expect count for QType F")
	}
}

func TestDecodeNextPacketQCountOnlyIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0xAC}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete Q count packet, got %v", err)
	}
}

func TestDecodeNextPacketQShortAddrIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0xA6, 0x80}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete Q short address, got %v", err)
	}
}

func TestDecodeNextPacketQLongAddrIncompleteFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0xAB, 0x02, 0x01, 0x34}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for incomplete Q long address, got %v", err)
	}
}

func TestDecodeNextPacketContextNoUpdate(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x80}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktCtxt {
		t.Fatalf("expected PktCtxt, got %v", pkt.Type)
	}
	if pkt.Valid.Context {
		t.Fatalf("did not expect context valid for no-update packet")
	}
}

func TestDecodeNextPacketContextInfoNoIDs(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x81, 0x19}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	if pkt.Type != PktCtxt {
		t.Fatalf("expected PktCtxt, got %v", pkt.Type)
	}
	if !pkt.Valid.Context || !pkt.Context.Updated {
		t.Fatalf("expected updated valid context packet")
	}
	if pkt.Context.EL != 0x1 || !pkt.Context.NSE || !pkt.Context.SF || pkt.Context.NS {
		t.Fatalf("unexpected context decode: %+v", pkt.Context)
	}
}

func TestDecodeNextPacketContextWithIDsFallsBack(t *testing.T) {
	_, _, err := decodeNextPacket([]byte{0x81, 0x40}, 0)
	if !errors.Is(err, errDecodeNotImplemented) {
		t.Fatalf("expected errDecodeNotImplemented for config-sized context payload, got %v", err)
	}
}

func TestDecodeNextPacketDataSyncMarkers(t *testing.T) {
	pkt, consumed, err := decodeNextPacket([]byte{0x23}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktNumDsMkr || pkt.DsmVal != 0x3 {
		t.Fatalf("unexpected numbered DSM decode: type=%v dsm=%d", pkt.Type, pkt.DsmVal)
	}

	pkt, consumed, err = decodeNextPacket([]byte{0x2A}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if pkt.Type != PktUnnumDsMkr || pkt.DsmVal != 0x2 {
		t.Fatalf("unexpected unnumbered DSM decode: type=%v dsm=%d", pkt.Type, pkt.DsmVal)
	}
}

func TestProcessDataFastPathContextNoIDUpdatePreservesIDs(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	p.currPacket.Context.VMID = 0xAA
	p.currPacket.Context.CtxtID = 0xBBCC

	consumed, err := p.processData(0, []byte{0x81, 0x31})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 2 {
		t.Fatalf("expected 2 bytes consumed, got %d", consumed)
	}
	// Packet output resets Updated/Valid flags, but context values persist across packets.
	if p.currPacket.Context.Updated {
		t.Fatalf("expected Updated cleared after packet reset")
	}
	if p.currPacket.Context.EL != 0x1 || !p.currPacket.Context.SF || !p.currPacket.Context.NS {
		t.Fatalf("expected context info fields updated, got %+v", p.currPacket.Context)
	}
	if p.currPacket.Context.VMID != 0xAA || p.currPacket.Context.CtxtID != 0xBBCC {
		t.Fatalf("expected VMID/CtxtID to be preserved, got vmid=0x%X ctxt=0x%X", p.currPacket.Context.VMID, p.currPacket.Context.CtxtID)
	}
}

func TestProcessDataFastPathDataSyncMarkerSetsDsmVal(t *testing.T) {
	p := NewProcessor(&Config{RegIdr0: 0x18, RegConfigr: 0x2 | (1 << 16)})
	p.isSync = true

	consumed, err := p.processData(0, []byte{0x23})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 1 {
		t.Fatalf("expected 1 byte consumed, got %d", consumed)
	}
	if p.currPacket.DsmVal != 0x3 {
		t.Fatalf("expected DsmVal 3, got %d", p.currPacket.DsmVal)
	}
}

func TestProcessDataFastPathAddrContext32PreservesUpperIn64BitContext(t *testing.T) {
	p := NewProcessor(&Config{})
	p.isSync = true
	p.currPacket.VAddr = 0x11223344AABBCCDD
	p.currPacket.VAddrValidBits = 64
	p.currPacket.Valid.Context = true
	p.currPacket.Context.SF = true
	p.currPacket.Context.VMID = 0xAA

	consumed, err := p.processData(0, []byte{0x82, 0x04, 0x00, 0x34, 0x12, 0x01})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if consumed != 6 {
		t.Fatalf("expected 6 bytes consumed, got %d", consumed)
	}
	if p.currPacket.VAddr != 0x1122334412340010 {
		t.Fatalf("expected merged address 0x1122334412340010, got 0x%X", p.currPacket.VAddr)
	}
	if p.currPacket.Context.VMID != 0xAA {
		t.Fatalf("expected VMID preserved, got 0x%X", p.currPacket.Context.VMID)
	}
}
