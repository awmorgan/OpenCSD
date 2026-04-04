package etmv4

import (
	"errors"
	"testing"

	"opencsd/internal/ocsd"
)

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
