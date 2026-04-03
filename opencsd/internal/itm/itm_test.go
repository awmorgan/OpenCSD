package itm

import (
	"errors"
	"io"
	"testing"

	"opencsd/internal/ocsd"
)

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

func TestITMEndToEndDecode(t *testing.T) {
	runDecode := func(stream []byte) []ocsd.TraceElement {
		cfg := &Config{}
		cfg.SetTraceID(0x11)

		proc, dec, err := NewPipeline(0, cfg, nil, nil)
		if err != nil {
			t.Fatalf("NewPipeline failed: %v", err)
		}

		proc.TraceDataIn(ocsd.OpData, 0, stream)
		proc.TraceDataIn(ocsd.OpFlush, 0, nil)
		proc.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(len(stream)), nil)

		elems := make([]ocsd.TraceElement, 0)
		for {
			elem, nextErr := dec.Next()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				t.Fatalf("decoder next failed: %v", nextErr)
			}
			elems = append(elems, *elem)
		}
		return elems
	}

	t.Run("SWITAndDWT", func(t *testing.T) {
		sb := &ItmStreamBuilder{}
		sb.AddBytes(0xF0, 0x00, 0x34)
		sb.AddAsync()
		sb.AddOverflow()
		sb.AddSWIT(3, 0xBB, 1)
		sb.AddSWIT(1, 0x2345, 2)
		sb.AddSWIT(1, 0x67890123, 3)
		sb.AddDWT(0, 0x15, 1)
		sb.AddDWT(1, 0x12, 2)
		sb.AddDWT(2, 0x1000, 3)
		sb.AddDWT(0x10, 0x44, 1)
		sb.AddDWT(0x11, 0x33, 1)
		sb.AddDWT(0x04, 0x2000, 3)
		sb.AddDWT(0x05, 0x1000, 2)

		elems := runDecode(sb.data)
		if len(elems) == 0 {
			t.Fatalf("expected parsed trace elements for SWIT/DWT stream")
		}
		for i, el := range elems {
			if el.String() == "" {
				t.Fatalf("element %d rendered empty string", i)
			}
		}
	})

	t.Run("TimestampAndExtension", func(t *testing.T) {
		sb := &ItmStreamBuilder{}
		sb.AddAsync()
		sb.AddLTSSync(2)
		sb.AddLTS(1, 0x3220, 2)
		sb.AddBytes(0x94, 0x7A)
		sb.AddBytes(0x94, 0x82, 0x7A)
		sb.AddBytes(0xB4, 0x00)
		sb.AddBytes(0xB4, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
		sb.AddBytes(0x08)
		sb.AddBytes(0x0C, 0x80, 0x00)

		elems := runDecode(sb.data)
		if len(elems) == 0 {
			t.Fatalf("expected parsed trace elements for timestamp/extension stream")
		}
		for i, el := range elems {
			if el.String() == "" {
				t.Fatalf("element %d rendered empty string", i)
			}
		}
	})

	t.Run("MixedEndToEnd", func(t *testing.T) {
		sb := &ItmStreamBuilder{}
		sb.AddBytes(0xF0, 0x00, 0x34)
		sb.AddAsync()
		sb.AddOverflow()
		sb.AddSWIT(2, 0xAB, 1)
		sb.AddDWT(0x10, 0x44, 1)
		sb.AddLTSSync(1)
		sb.AddBytes(0x94, 0x7A)
		sb.AddBytes(0x08)

		elems := runDecode(sb.data)
		if len(elems) == 0 {
			t.Fatalf("expected parsed trace elements for mixed stream")
		}
		for i, el := range elems {
			if el.String() == "" {
				t.Fatalf("element %d rendered empty string", i)
			}
		}
	})
}

func TestITMTypedConstructors(t *testing.T) {
	t.Run("PipelineCreation", func(t *testing.T) {
		cfg := &Config{}
		cfg.SetTraceID(0x21)

		proc, dec, err := NewPipeline(3, cfg, nil, nil)
		if err != nil {
			t.Fatalf("NewPipeline failed: %v", err)
		}
		if proc == nil {
			t.Fatal("expected non-nil processor")
		}
		if dec == nil {
			t.Fatal("expected non-nil decoder")
		}
		if proc.Config != cfg {
			t.Fatal("expected processor to keep typed config")
		}
		if dec.Config != cfg {
			t.Fatal("expected decoder to keep typed config")
		}
		if got := proc.PktOut(); got != dec {
			t.Fatal("expected pipeline constructor to wire processor output to decoder")
		}
	})

	t.Run("PipelineWithDependencies", func(t *testing.T) {
		cfg := &Config{}
		cfg.SetTraceID(0x24)

		proc, dec, err := NewPipeline(5, cfg, nil, nil)
		if err != nil {
			t.Fatalf("NewPipeline with deps failed: %v", err)
		}
		if proc == nil || dec == nil {
			t.Fatal("expected non-nil processor and decoder")
		}
		if got := proc.PktOut(); got != dec {
			t.Fatal("expected pipeline constructor to wire processor output to decoder")
		}
	})

	t.Run("RejectNilConfig", func(t *testing.T) {
		if proc, dec, err := NewPipeline(0, nil, nil, nil); proc != nil || dec != nil || !errors.Is(err, ocsd.ErrInvalidParamVal) {
			t.Fatalf("expected nil-config pipeline constructor to fail with ErrInvalidParamVal, got proc=%v dec=%v err=%v", proc, dec, err)
		}
	})
}

func TestITMErrorCases(t *testing.T) {
	cfg := &Config{}
	proc := NewPktProc(nil)
	proc.SetProtocolConfig(cfg)

	// reserved header error
	sb := &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0x14) // reserved

	_, err := proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp := ocsd.DataRespFromErr(err)
	if ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected non-fatal by default")
	}

	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_ = proc.ApplyFlags(ocsd.OpflgPktprocErrBadPkts)
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for reserved header (Resp = %v)", resp)
	}

	// bad sequence GTS1
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0x94, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for GTS1 limit exceeded")
	}

	// bad sequence GTS2
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0xB4, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for GTS2 limit exceeded")
	}

	// bad sequence Local TS
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0xC0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
	if !ocsd.DataRespIsFatal(resp) {
		t.Errorf("Expected fatal response for LTS limit exceeded")
	}

	// bad sequence Extension
	sb = &ItmStreamBuilder{}
	sb.AddAsync()
	sb.AddBytes(0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00)
	proc.TraceDataIn(ocsd.OpReset, 0, nil)
	_, err = proc.TraceDataIn(ocsd.OpData, 0, sb.data)
	resp = ocsd.DataRespFromErr(err)
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

	// bad-packet hook
	proc.IsBadPacket()

	// Decoder missing config test
	if dec, err := NewPktDecode(nil); dec != nil || !errors.Is(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected invalid-param error for nil config, got dec=%v err=%v", dec, err)
	}
}

func TestITMPacketStringVariants(t *testing.T) {
	pkt := &Packet{}
	pkt.Reset()
	if pkt.String() != "ITM_RESERVED: ; 'Reserved Packet Header'" {
		t.Errorf("Unexpected string: %s", pkt.String())
	}

	pkt.SetValue(0xFFFFFFFF, 1)
	if pkt.Value != 0xFF || pkt.ValSz != 1 {
		t.Fatalf("SetValue 8-bit masking failed: value=0x%X size=%d", pkt.Value, pkt.ValSz)
	}
	pkt.SetValue(0x12345678, 2)
	if pkt.Value != 0x5678 || pkt.ValSz != 2 {
		t.Fatalf("SetValue 16-bit masking failed: value=0x%X size=%d", pkt.Value, pkt.ValSz)
	}
	pkt.SetValue(0xABCDEF12, 3)
	if pkt.Value != 0xCDEF12 || pkt.ValSz != 3 {
		t.Fatalf("SetValue 24-bit masking failed: value=0x%X size=%d", pkt.Value, pkt.ValSz)
	}
	pkt.SetValue(0x12345678, 0)
	if pkt.Value != 0x12345678 || pkt.ValSz != 4 {
		t.Fatalf("SetValue size clamp failed: value=0x%X size=%d", pkt.Value, pkt.ValSz)
	}

	pkt.Type = PktDWT
	pkt.SrcID = 0
	pkt.SetValue(0x15, 1) // CPI, SLP, FLD
	str := pkt.String()
	if str == "" {
		t.Fatalf("expected non-empty DWT string")
	}

	pkt.Type = PktSWIT
	pkt.SrcID = 3
	pkt.SetValue(0xAA, 1)
	str = pkt.String()
	if str == "" {
		t.Fatalf("expected non-empty SWIT string")
	}

	pkt.Type = PktBadSequence
	if !pkt.IsBadPacket() {
		t.Errorf("Expected bad packet")
	}
	pkt.Type = PktSWIT

	pkt.Type = PktTSLocal
	for id := range uint8(4) {
		pkt.SrcID = id
		pkt.SetValue(0x10, 2)
		if pkt.String() == "" {
			t.Fatalf("expected non-empty local TS string for id=%d", id)
		}
	}

	pkt.Type = PktTSGlobal1
	pkt.SetValue(0x100, 3)
	if pkt.String() == "" {
		t.Fatalf("expected non-empty global TS1 string")
	}

	pkt.Type = PktTSGlobal2
	pkt.SetExtValue(0x1000)
	if pkt.String() == "" {
		t.Fatalf("expected non-empty global TS2 string")
	}

	pkt.Type = PktExtension
	pkt.SrcID = 0
	if pkt.String() == "" {
		t.Fatalf("expected non-empty extension SW string")
	}

	pkt.Type = PktExtension
	pkt.SrcID = 0x80
	if pkt.String() == "" {
		t.Fatalf("expected non-empty extension HW string")
	}

	pkt.Type = PktOverflow
	if pkt.String() == "" {
		t.Fatalf("expected non-empty overflow string")
	}

	// valSize coverage
	pkt.ValSz = 0
	pkt.Type = PktDWT
	if pkt.String() == "" {
		t.Fatalf("expected non-empty DWT string for val size 0")
	}
	pkt.ValSz = 2
	if pkt.String() == "" {
		t.Fatalf("expected non-empty DWT string for val size 2")
	}
	pkt.ValSz = 4
	if pkt.String() == "" {
		t.Fatalf("expected non-empty DWT string for val size 4")
	}
	pkt.ValSz = 1

	// DWT detailed coverage
	for _, id := range []uint8{1, 2, 8, 9, 16, 18, 99} {
		pkt.SrcID = id
		if pkt.String() == "" {
			t.Fatalf("expected non-empty DWT string for src id %d", id)
		}
	}

	types := []PktType{
		PktNotSync, PktIncompleteEOT, PktAsync, PktOverflow,
		PktSWIT, PktDWT, PktTSLocal, PktTSGlobal1, PktTSGlobal2, PktExtension,
		PktBadSequence, PktReserved, PktType(99),
	}
	for _, pktType := range types {
		pkt.Type = pktType
		if pkt.String() == "" {
			t.Fatalf("expected non-empty packet string for type %v", pktType)
		}
	}
}

func TestExtractContVal_SliceUnderflow(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("extractContVal32 panicked: %v", r)
		}
	}()
	proc := PktProc{}
	proc.packetData = []byte{}
	proc.extractContVal32()
}
