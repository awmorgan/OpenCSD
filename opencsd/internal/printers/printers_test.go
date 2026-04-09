package printers

import (
	"bytes"
	"strings"
	"testing"

	"opencsd/internal/ocsd"
)

func TestItemPrinter(t *testing.T) {
	var buf bytes.Buffer
	p := NewItemPrinter(&buf)

	p.SetMute(true)
	if !p.IsMuted() {
		t.Error("expected muted")
	}

	p.SetTestWaits(5)
	if p.TestWaits() != 5 {
		t.Error("expected 5 waits")
	}
	p.DecTestWaits()
	if p.TestWaits() != 4 {
		t.Error("expected 4 waits")
	}

	p.MuteIDPrint(true)
	if !p.IDPrintMuted() {
		t.Error("expected id print muted")
	}

	p.ItemPrintLine("Hello Test\n")
	if buf.String() != "Hello Test\n" {
		t.Errorf("buf string mismatch: %q", buf.String())
	}
}

func TestRawFramePrinter(t *testing.T) {
	var buf bytes.Buffer
	rp := NewRawFramePrinter(&buf)

	// Test muted
	rp.SetMute(true)
	err := rp.WriteRawFrame(0, ocsd.FrmPacked, nil, 0)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
	rp.SetMute(false)

	// Test control methods
	err = rp.FlushRawFrames()
	if err != nil {
		t.Errorf("Expected nil error for flush, got %v", err)
	}
	err = rp.ResetRawFrames()
	if err != nil {
		t.Errorf("Expected nil error for reset, got %v", err)
	}
	err = rp.CloseRawFrames()
	if err != nil {
		t.Errorf("Expected nil error for close, got %v", err)
	}

	tests := []struct {
		desc    string
		index   ocsd.TrcIndex
		elem    ocsd.RawframeElem
		traceID uint8
		data    []byte
		exptStr string
	}{
		{
			desc:    "RAW_PACKED",
			index:   10,
			elem:    ocsd.FrmPacked,
			exptStr: "Frame Data; Index     10;    RAW_PACKED; \n",
		},
		{
			desc:    "HSYNC",
			index:   200,
			elem:    ocsd.FrmHsync,
			exptStr: "Frame Data; Index    200;         HSYNC; \n",
		},
		{
			desc:    "FSYNC",
			index:   9999999,
			elem:    ocsd.FrmFsync,
			exptStr: "Frame Data; Index9999999;         FSYNC; \n",
		},
		{
			desc:    "ID_DATA normal",
			index:   0,
			elem:    ocsd.FrmIDData,
			traceID: 0x1A,
			exptStr: "Frame Data; Index      0;   ID_DATA[0x1a]; \n",
		},
		{
			desc:    "ID_DATA bad src",
			index:   1,
			elem:    ocsd.FrmIDData,
			traceID: ocsd.BadCSSrcID,
			exptStr: "Frame Data; Index      1;   ID_DATA[????]; \n",
		},
		{
			desc:    "UNKNOWN",
			index:   5,
			elem:    ocsd.FrmNone,
			exptStr: "Frame Data; Index      5;       UNKNOWN; \n",
		},
		{
			desc:    "With Data",
			index:   42,
			elem:    ocsd.FrmPacked,
			data:    []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34},
			exptStr: "Frame Data; Index     42;    RAW_PACKED; 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff \n12 34 \n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			buf.Reset()
			rp.WriteRawFrame(tc.index, tc.elem, tc.data, tc.traceID)
			if buf.String() != tc.exptStr {
				t.Errorf("\nexpected:\n%q\nactual:\n%q", tc.exptStr, buf.String())
			}
		})
	}
}

func TestGenericElementPrinter(t *testing.T) {
	var buf bytes.Buffer
	gp := NewGenericElementPrinter(&buf)

	// Test muted
	gp.SetMute(true)
	elem := ocsd.NewTraceElementWithType(ocsd.GenElemTraceOn)
	elem.Index = 123
	elem.TraceID = 0x10
	err := gp.PrintElement(elem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output while muted")
	}
	gp.SetMute(false)

	// test mute id print
	gp.MuteIDPrint(true)
	elem.Index = 100
	elem.TraceID = 0x11
	gp.PrintElement(elem)
	if strings.Contains(buf.String(), "Idx:100; ID:11;") {
		t.Errorf("did not expect id output, got %q", buf.String())
	}
	gp.MuteIDPrint(false)
	buf.Reset()

	// standard elem test
	elem.Index = 200
	elem.TraceID = 0x22
	gp.PrintElement(elem)
	expt := "Idx:200; ID:22; OCSD_GEN_TRC_ELEM_TRACE_ON( [begin or filter])\n"
	if buf.String() != expt {
		t.Errorf("expected %q, got %q", expt, buf.String())
	}
	buf.Reset()

	// Test wait functionality
	gp.SetTestWaits(1)
	elem.Index = 300
	elem.TraceID = 0x33
	err = gp.PrintElement(elem)
	if !ocsd.IsDataWaitErr(err) {
		t.Fatalf("expected wait sentinel error, got %v", err)
	}
	if !gp.NeedAckWait() {
		t.Errorf("expected need ack wait to be true")
	}

	buf.Reset()
	// Next element without ack wait
	elem.Index = 301
	elem.TraceID = 0x33
	gp.PrintElement(elem)
	if !strings.Contains(buf.String(), "WARNING") {
		t.Errorf("expected warning for unacknowledged wait, got %s", buf.String())
	}
	if gp.NeedAckWait() {
		t.Errorf("expected ack wait to be false after warning")
	}
	buf.Reset()

	// with ack wait
	gp.SetTestWaits(1)
	elem.Index = 400
	elem.TraceID = 0x44
	gp.PrintElement(elem) // sets needAckWait = true
	gp.AckWait()          // manual clear
	buf.Reset()
	elem.Index = 401
	elem.TraceID = 0x44
	gp.PrintElement(elem)
	if strings.Contains(buf.String(), "WARNING") {
		t.Errorf("did not expect warning, got %s", buf.String())
	}

	// Test collect stats
	gp.SetCollectStats()
	ctxElemA := ocsd.NewTraceElementWithType(ocsd.GenElemPeContext)
	ctxElemA.Index = 500
	ctxElemA.TraceID = 0x55
	gp.PrintElement(ctxElemA)
	ctxElemB := ocsd.NewTraceElementWithType(ocsd.GenElemPeContext)
	ctxElemB.Index = 501
	ctxElemB.TraceID = 0x55
	gp.PrintElement(ctxElemB)

	buf.Reset()
	gp.PrintStats()
	if !strings.Contains(buf.String(), "OCSD_GEN_TRC_ELEM_TRACE_ON : 0") {
		t.Errorf("expected trace on count 0, got %s", buf.String())
	}
	if !strings.Contains(buf.String(), "OCSD_GEN_TRC_ELEM_PE_CONTEXT : 2") {
		t.Errorf("expected pe context count 2, got %s", buf.String())
	}

	// Out of bounds elemName check
	if nm := elemName(ocsd.GenElemType(999)); nm != "OCSD_GEN_TRC_ELEM_UNKNOWN" {
		t.Errorf("expected unknown, got %s", nm)
	}
}
