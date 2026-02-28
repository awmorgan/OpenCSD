package itm

import (
	"fmt"
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

type ItmStreamBuilder struct {
	data []byte
}

func (b *ItmStreamBuilder) AddBytes(v ...byte) {
	b.data = append(b.data, v...)
}

func (b *ItmStreamBuilder) AddAsync() {
	b.AddBytes(0x00, 0x00, 0x00, 0x00, 0x00, 0x80)
}

func (b *ItmStreamBuilder) AddOverflow() {
	b.AddBytes(0x70)
}

func (b *ItmStreamBuilder) AddSWIT(chanID uint8, val uint32, size uint8) {
	hdr := ((chanID & 0x1F) << 3) | (size & 0x3)
	b.AddBytes(hdr)
	b.AddVal(val, size)
}

func (b *ItmStreamBuilder) AddDWT(discID uint8, val uint32, size uint8) {
	hdr := ((discID & 0x1F) << 3) | 0x04 | (size & 0x3)
	b.AddBytes(hdr)
	b.AddVal(val, size)
}

func (b *ItmStreamBuilder) AddVal(val uint32, size uint8) {
	if size >= 1 {
		b.AddBytes(byte(val & 0xFF))
	}
	if size >= 2 {
		b.AddBytes(byte((val >> 8) & 0xFF))
	}
	if size == 3 { // size 3 maps to 4 bytes in ITM
		b.AddBytes(byte((val>>16)&0xFF), byte((val>>24)&0xFF))
	}
}

func (b *ItmStreamBuilder) AddLTS(tc uint8, val uint32, size uint8) {
	hdr := ((tc & 0x3) << 4) | 0x80 | 0x40 // TS_CONT | TS_TC_BIT
	b.AddBytes(hdr)
	b.addContVal(uint64(val), size)
}

func (b *ItmStreamBuilder) AddLTSSync(val uint8) {
	hdr := (val & 0x7) << 4 // No desc TS_SYNC
	b.AddBytes(hdr)
}

func (b *ItmStreamBuilder) AddGTS1(time uint32, wrap uint8, clkCh uint8, size uint8) {
	b.AddBytes(0x94) // GTS1 Header
	// The 4th byte (if size allows) contains wrap and clkCh
	// But our extract function relies on sequence.
	b.addContVal(uint64(time), size)
	// We might need to manually inject wrap/clkCh if size=4 (5 bytes total)
	// It's more complex, let's keep basic coverage.
}

func (b *ItmStreamBuilder) addContVal(val uint64, numBytes uint8) {
	for i := uint8(0); i < numBytes-1; i++ {
		b.AddBytes(byte((val & 0x7F) | 0x80))
		val >>= 7
	}
	b.AddBytes(byte(val & 0x7F))
}

func (b *ItmStreamBuilder) AddExtension(srcHW bool, nSize uint8, val uint32, numBytes uint8) {
	hdr := uint8(0x08) // extension base
	if srcHW {
		hdr |= 0x4
	}
	// encoding nSize and val is complex, just test a simple 1 byte extension.
	b.AddBytes(hdr)
}

func TestITMPrehensive(t *testing.T) {
	cfg := NewConfig()
	cfg.SetTraceID(0x11)

	manager := NewDecoderManager()
	proc := manager.CreatePktProc(0, cfg).(*PktProc)
	dec := manager.CreatePktDecode(0, cfg).(*PktDecode)

	proc.PktOutI.Attach(dec)
	outReceiver := &testTrcElemIn{}
	dec.TraceElemOut.Attach(outReceiver)

	sb := &ItmStreamBuilder{}

	// initial unsynced
	sb.AddBytes(0xF0, 0x00, 0x34)
	sb.AddAsync()

	sb.AddOverflow()

	// SWIT tests
	sb.AddSWIT(3, 0xBB, 1)       // 8 bit
	sb.AddSWIT(1, 0x2345, 2)     // 16 bit
	sb.AddSWIT(1, 0x67890123, 3) // 32 bit (size 3)

	// DWT tests
	sb.AddDWT(0, 0x15, 1)      // EVENT CPI, SLP, FLD etc. (0x15 = 0x01 | 0x04 | 0x10)
	sb.AddDWT(1, 0x12, 2)      // EXCEP Enter
	sb.AddDWT(2, 0x1000, 3)    // PC Sample
	sb.AddDWT(0x10, 0x44, 1)   // DT Data Read (cmpn 0 = 0x10)
	sb.AddDWT(0x11, 0x33, 1)   // DT Data Write (cmpn 0 = 0x11)
	sb.AddDWT(0x04, 0x2000, 3) // DT PC value (cmpn 0 = 0x04)
	sb.AddDWT(0x05, 0x1000, 2) // DT ADDR value (cmpn 0 = 0x05)

	// Local TS
	sb.AddLTSSync(2)        // single byte sync
	sb.AddLTS(1, 0x3220, 2) // multi-byte delay

	// Global TS
	sb.AddBytes(0x94, 0x7A)                               // GTS1 small
	sb.AddBytes(0x94, 0x82, 0x7A)                         // GTS1 mid
	sb.AddBytes(0xB4, 0x00)                               // GTS2 small
	sb.AddBytes(0xB4, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00) // GTS2 64-bit (size > 5)

	// Extension
	sb.AddBytes(0x08)             // page 0 (simple extension SW)
	sb.AddBytes(0x0C, 0x80, 0x00) // HW extension size 9 bit (0x0C = 0x08 | 0x04)

	proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	proc.TraceDataIn(ocsd.OpFlush, 0, nil)
	proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(sb.data)), nil)

	if len(outReceiver.elements) == 0 {
		t.Errorf("Expected parsed trace elements, but got 0. Did proc even parse packets? pktCount=%d, eot=%v", len(outReceiver.elements), proc.ComponentOpMode())
	}

	for i, el := range outReceiver.elements {
		fmt.Printf("Element %d: %s\n", i, el.String())
	}
}

func TestITMErrorCases(t *testing.T) {
	cfg := NewConfig()
	proc := NewPktProc(0)
	proc.SetProtocolConfig(cfg)

	// reserved header error
	sb := &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0x14) // reserved

	_, resp := proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal by default")
	}

	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	proc.SetComponentOpMode(ocsd.OpflgPktprocErrBadPkts)
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for reserved header (Mode = %x, Resp = %v)", proc.ComponentOpMode(), resp)
	}

	// bad sequence GTS1
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0x94, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for GTS1 limit exceeded")
	}

	// bad sequence GTS2
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0xB4, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for GTS2 limit exceeded")
	}

	// bad sequence Local TS
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0xC0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for LTS limit exceeded")
	}

	// bad sequence Extension
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, resp = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for Extension limit exceeded")
	}

	// Incomplete EOT
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0x94)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	proc.TraceDataIn(ocsd.OpEOT, 0, nil)

	// Async while synced
	sb = &ItmStreamBuilder{}
	sb.AddAsync() // triggers sync
	sb.AddAsync() // processed while synced
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	proc.TraceDataIn(ocsd.OpData, 0, sb.data)

	// isBadPacket callback
	proc.FnIsBadPacket()

	// Decoder missing config test
	dec := NewPktDecode(0)
	dec.FnOnProtocolConfig()
	dec.FnOnFlush()
	dec.FnOnReset()
}

func TestITMPacketString(t *testing.T) {
	pkt := &Packet{}
	pkt.InitPacket()
	if pkt.String() != "NOTSYNC:ITM not synchronised" {
		t.Errorf("Unexpected string: %s", pkt.String())
	}

	pkt.SetPacketType(PktDWT)
	pkt.SetSrcID(0)
	pkt.SetValue(0x15, 1) // CPI, SLP, FLD
	str := pkt.String()
	fmt.Printf("DWT Str: %s\n", str)

	pkt.SetPacketType(PktSWIT)
	pkt.SetSrcID(3)
	pkt.SetValue(0xAA, 1)
	str = pkt.String()
	fmt.Printf("SWIT Str: %s\n", str)

	pkt.UpdateErrType(PktBadSequence)
	if !pkt.IsBadPacket() {
		t.Errorf("Expected bad packet")
	}

	pkt.SetPacketType(PktTSLocal)
	for id := uint8(0); id < 4; id++ {
		pkt.SetSrcID(id)
		pkt.SetValue(0x10, 2)
		fmt.Printf("LocalTS Str %d: %s\n", id, pkt.String())
	}

	pkt.SetPacketType(PktTSGlobal1)
	pkt.SetValue(0x100, 3)
	fmt.Printf("GlobalTS Str: %s\n", pkt.String())

	pkt.SetPacketType(PktTSGlobal2)
	pkt.SetExtValue(0x1000)
	fmt.Printf("GlobalTS2 Str: %s\n", pkt.String())

	pkt.SetPacketType(PktExtension)
	pkt.SetSrcID(0)
	fmt.Printf("Ext Str: %s\n", pkt.String())

	pkt.SetPacketType(PktExtension)
	pkt.SetSrcID(0x80)
	fmt.Printf("Ext HW Str: %s\n", pkt.String())

	pkt.SetPacketType(PktOverflow)
	fmt.Printf("Overflow Str: %s\n", pkt.String())

	// valSize coverage
	pkt.ValSz = 0
	pkt.SetPacketType(PktDWT)
	pkt.String()
	pkt.ValSz = 2
	pkt.String()
	pkt.ValSz = 4
	pkt.String()
	pkt.ValSz = 1

	// DWT detailed coverage
	for _, id := range []uint8{1, 2, 8, 9, 16, 18, 99} {
		pkt.SetSrcID(id)
		pkt.String()
	}

	types := []PktType{
		PktNotSync, PktIncompleteEOT, PktNoErrType, PktAsync, PktOverflow,
		PktSWIT, PktDWT, PktTSLocal, PktTSGlobal1, PktTSGlobal2, PktExtension,
		PktBadSequence, PktReserved, PktType(99),
	}
	for _, t := range types {
		pkt.SetPacketType(t)
		pkt.String()
	}
}
