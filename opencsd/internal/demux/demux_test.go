package demux

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

var (
	baseCfg uint32 = ocsd.DfrmtrFrameMemAlign | ocsd.DfrmtrPackedRawOut | ocsd.DfrmtrUnpackedRawOut
)

func idByteID(id uint8) byte {
	return (id << 1) | 0x01
}

func idByteData(data uint8) byte {
	return data & 0xFE
}

func flagsByte(id0, id1, id2, id3, id4, id5, id6, id7 byte) byte {
	return ((id7 & 1) << 7) | ((id6 & 1) << 6) | ((id5 & 1) << 5) | ((id4 & 1) << 4) |
		((id3 & 1) << 3) | ((id2 & 1) << 2) | ((id1 & 1) << 1) | (id0 & 1)
}

func hsyncBytes() []byte { return []byte{0xff, 0x7f} }
func fsyncBytes() []byte { return []byte{0xff, 0xff, 0xff, 0x7f} }

func makeBufHsyncFsync() []byte {
	b := []byte{}
	b = append(b, fsyncBytes()...)
	b = append(b, idByteID(0x10), 0x01, idByteData(0x2), 0x03)
	b = append(b, hsyncBytes()...)
	b = append(b, idByteID(0x20), 0x4, idByteData(0x5), 0x6, idByteData(0x7), 0x08)
	b = append(b, hsyncBytes()...)
	b = append(b, idByteData(0x9), 0xA, idByteID(0x10), 0x0B, idByteData(0xC), flagsByte(0, 0, 0, 1, 1, 1, 1, 0))
	return b
}

func makeBufMemAlign() []byte {
	return []byte{
		idByteID(0x10), 0x01, idByteData(0x02), 0x03,
		idByteData(0x04), 0x05, idByteData(0x06), 0x07,
		idByteID(0x20), 0x08, idByteData(0x09), 0x0A,
		idByteData(0x0B), 0x0C, idByteData(0x0D), flagsByte(0, 0, 0, 0, 0, 1, 1, 1),
		idByteData(0x0E), 0x0F, idByteID(0x30), 0x10,
		idByteData(0x11), 0x12, idByteData(0x13), 0x14,
		idByteData(0x15), 0x16, idByteID(0x10), 0x17,
		idByteData(0x18), 0x19, idByteData(0x20), flagsByte(0, 0, 1, 1, 1, 1, 0, 0),
	}
}

func makeBufMemAlign8Id() []byte {
	return []byte{
		idByteID(0x10), 0x01, idByteData(0x02), 0x03,
		idByteData(0x04), 0x05, idByteData(0x06), 0x07,
		idByteID(0x20), 0x08, idByteData(0x09), 0x0A,
		idByteData(0x0B), 0x0C, idByteData(0x0D), flagsByte(0, 0, 0, 0, 0, 1, 1, 1),
		idByteID(0x01), 0x0E, idByteID(0x02), 0x0F,
		idByteID(0x03), 0x10, idByteID(0x04), 0x11,
		idByteID(0x05), 0x12, idByteID(0x06), 0x13,
		idByteID(0x07), 0x14, idByteData(0x50), flagsByte(1, 1, 1, 1, 1, 1, 1, 1),
		idByteData(0x15), 0x16, idByteData(0x17), 0x18,
		idByteData(0x19), 0x1A, idByteData(0x1B), 0x1C,
		idByteID(0x20), 0x1D, idByteData(0x1E), 0x1F,
		idByteData(0x20), 0x21, idByteData(0x22), flagsByte(1, 1, 1, 1, 0, 0, 0, 0),
	}
}

func makeBufMemAlignStRst() []byte {
	b := []byte{}
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, makeBufMemAlign()...)
	return b
}

func makeBufMemAlignMidRst() []byte {
	b := []byte{}
	half1 := makeBufMemAlign()[:16]
	half2 := makeBufMemAlign()[16:]
	b = append(b, half1...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, half2...)
	return b
}

func makeBufMemAlignEnRst() []byte {
	b := []byte{}
	b = append(b, makeBufMemAlign()...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	b = append(b, fsyncBytes()...)
	return b
}

func makeBufBadData() []byte {
	return []byte{
		0xff, 0xff, 0xff, 0x7f, 0x30, 0xff, 0x53, 0x54, 0x4d, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0, 0x36, 0xff, 0xb1, 0xff, 0x36, 0x36, 0x36, 0x36, 0x36, 0x2b,
		0x36, 0x36, 0x3a, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0,
		0, 0x2c, 0, 0, 0, 0x32, 0x1, 0,
	}
}

type TestLogger struct {
	lastErr ocsd.Err
}

func (l *TestLogger) LogError(err *common.Error) {
	if err != nil {
		l.lastErr = err.Code
	}
}

func (l *TestLogger) LogMessage(s ocsd.ErrSeverity, msg string) {
}

type mockRawSink struct {
	out *bytes.Buffer
}

func (m *mockRawSink) TraceRawFrameIn(op ocsd.DatapathOp, index ocsd.TrcIndex, frameElem ocsd.RawframeElem, data []byte, traceID uint8) ocsd.DatapathResp {
	if op != ocsd.OpData {
		return ocsd.RespCont
	}

	var elemStr string
	switch frameElem {
	case ocsd.FrmPacked:
		elemStr = "   RAW_PACKED;"
	case ocsd.FrmHsync:
		elemStr = "        HSYNC;"
	case ocsd.FrmFsync:
		elemStr = "        FSYNC;"
	case ocsd.FrmIDData:
		if traceID == 0 || (traceID >= 0x70 && traceID <= 0x7F) {
			elemStr = "  ID_DATA[????];"
		} else {
			elemStr = fmt.Sprintf("  ID_DATA[0x%02x];", traceID)
		}
	}

	m.out.WriteString(fmt.Sprintf("Frame Data; Index %6d; %s", index, elemStr))

	for i, b := range data {
		if i > 0 {
			m.out.WriteString(" ")
		} else {
			m.out.WriteString(" ")
		}
		m.out.WriteString(fmt.Sprintf("%02x", b))
	}

	m.out.WriteString("\n")
	return ocsd.RespCont
}

// Global buffer and tracker to collect all Frame Data strings
var globalSinkOut = &bytes.Buffer{}

func resetDecoder(df *FrameDeformatter, t *testing.T) {
	_, resp := df.TraceDataIn(ocsd.OpReset, 0, nil)
	if resp != ocsd.RespCont {
		t.Errorf("Datapath error response on reset: %v", resp)
	}
}

func TestDemuxInit(t *testing.T) {
	df := NewFrameDeformatter()
	errLog := &TestLogger{}
	df.SetErrorLogger(errLog)

	if err := df.Configure(0); err != ocsd.ErrInvalidParamVal {
		t.Errorf("Expected OCSD_ERR_INVALID_PARAM_VAL for 0 flag config, got %v", err)
	}

	if err := df.Configure(0x80 | ocsd.DfrmtrFrameMemAlign); err != ocsd.ErrInvalidParamVal {
		t.Errorf("Expected OCSD_ERR_INVALID_PARAM_VAL for unknown flag config, got %v", err)
	}

	if err := df.Configure(ocsd.DfrmtrFrameMemAlign | ocsd.DfrmtrHasFsyncs); err != ocsd.ErrInvalidParamVal {
		t.Errorf("Expected OCSD_ERR_INVALID_PARAM_VAL for bad combo flag config, got %v", err)
	}
}

func TestRunMemAlignTest(t *testing.T) {
	df := NewFrameDeformatter()
	df.Configure(baseCfg)
	sink := &mockRawSink{out: globalSinkOut}
	df.SetRawTraceFrame(sink)
	errLog := &TestLogger{}
	df.SetErrorLogger(errLog)

	// 1
	resetDecoder(df, t)
	buf := makeBufMemAlign()
	processed, _ := df.TraceDataIn(ocsd.OpData, 0, buf)
	if processed != uint32(len(buf)) {
		t.Errorf("Size mismatch: in=%d out=%d", len(buf), processed)
	}

	// 2
	resetDecoder(df, t)
	buf2 := makeBufMemAlign8Id()
	processed, _ = df.TraceDataIn(ocsd.OpData, 0, buf2)
	if processed != uint32(len(buf2)) {
		t.Errorf("Size mismatch: in=%d out=%d", len(buf2), processed)
	}

	// 3
	df.Configure(baseCfg | ocsd.DfrmtrResetOn4xFsync)
	resetDecoder(df, t)
	buf3 := makeBufMemAlignStRst()
	processed, _ = df.TraceDataIn(ocsd.OpData, 0, buf3)
	if processed != uint32(len(buf3)) {
		t.Errorf("Size mismatch: in=%d out=%d", len(buf3), processed)
	}

	// 4
	resetDecoder(df, t)
	buf4 := makeBufMemAlignMidRst()
	processed, _ = df.TraceDataIn(ocsd.OpData, 0, buf4)
	if processed != uint32(len(buf4)) {
		t.Errorf("Size mismatch: in=%d out=%d", len(buf4), processed)
	}

	// 5
	resetDecoder(df, t)
	buf5 := makeBufMemAlignEnRst()
	processed, _ = df.TraceDataIn(ocsd.OpData, 0, buf5)
	if processed != uint32(len(buf5)) {
		t.Errorf("Size mismatch: in=%d out=%d", len(buf5), processed)
	}
}

func TestRunHSyncFSyncTest(t *testing.T) {
	df := NewFrameDeformatter()
	cfg := (baseCfg & ^uint32(ocsd.DfrmtrFrameMemAlign)) | ocsd.DfrmtrHasHsyncs | ocsd.DfrmtrHasFsyncs
	df.Configure(cfg)
	sink := &mockRawSink{out: globalSinkOut}
	df.SetRawTraceFrame(sink)
	errLog := &TestLogger{}
	df.SetErrorLogger(errLog)

	// 1
	resetDecoder(df, t)
	buf1 := makeBufHsyncFsync()
	processed, _ := df.TraceDataIn(ocsd.OpData, 0, buf1)
	if processed != uint32(len(buf1)) {
		t.Errorf("Size mismatch: in=%d out=%d", len(buf1), processed)
	}

	// 2 split
	resetDecoder(df, t)
	processed1, _ := df.TraceDataIn(ocsd.OpData, 0, buf1[:2])
	processed2, _ := df.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(processed1), buf1[processed1:])
	if processed1+processed2 != uint32(len(buf1)) {
		t.Errorf("Size mismatch: in=%d out=%d", len(buf1), processed1+processed2)
	}

	// 3 bad input
	resetDecoder(df, t)
	bufBad := makeBufBadData()
	_, resp := df.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(len(buf1)), bufBad)
	if resp != ocsd.RespFatalInvalidData || errLog.lastErr != ocsd.ErrDfrmtrBadFhsync {
		t.Errorf("Expected RespFatalInvalidData and ErrDfrmtrBadFhsync, got resp=%v err=%v", resp, errLog.lastErr)
	}
}

func TestRunDemuxBadDataTest(t *testing.T) {
	df := NewFrameDeformatter()
	df.Configure(baseCfg | ocsd.DfrmtrResetOn4xFsync)
	sink := &mockRawSink{out: globalSinkOut}
	df.SetRawTraceFrame(sink)
	errLog := &TestLogger{}
	df.SetErrorLogger(errLog)

	resetDecoder(df, t)
	bufBad := makeBufBadData()
	_, resp := df.TraceDataIn(ocsd.OpData, 0, bufBad)
	if resp != ocsd.RespFatalInvalidData || errLog.lastErr != ocsd.ErrDfrmtrBadFhsync {
		t.Errorf("Expected RespFatalInvalidData and ErrDfrmtrBadFhsync, got resp=%v err=%v", resp, errLog.lastErr)
	}
}

// Compare generated Frame Data with golden file
func TestGoldenFileVerification(t *testing.T) {
	globalSinkOut.Reset()
	// Re-run the tests sequentially to populate globalSinkOut in correct order
	TestRunMemAlignTest(t)
	TestRunHSyncFSyncTest(t)
	TestRunDemuxBadDataTest(t)

	actualLines := strings.Split(strings.TrimSpace(globalSinkOut.String()), "\n")

	goldenData, err := os.ReadFile("testdata/frame_demux_test.ppl")
	if err != nil {
		t.Fatalf("Failed to read golden file: %v", err)
	}

	var goldenLines []string
	scanner := bufio.NewScanner(bytes.NewReader(goldenData))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n\t ")
		if strings.HasPrefix(line, "Frame Data; Index ") {
			goldenLines = append(goldenLines, line)
		} else if len(goldenLines) > 0 && len(line) > 0 && ((line[0] >= '0' && line[0] <= '9') || (line[0] >= 'a' && line[0] <= 'f')) {
			goldenLines[len(goldenLines)-1] += " " + line
		}
	}

	minLen := len(actualLines)
	if len(goldenLines) < minLen {
		minLen = len(goldenLines)
	}

	mismatches := 0
	for i := 0; i < minLen; i++ {
		a := strings.TrimRight(actualLines[i], "\r\n\t ")
		g := goldenLines[i]
		if a != g {
			t.Errorf("Mismatch at line %d\nActual: '%s'\nGolden: '%s'", i+1, a, g)
			mismatches++
			if mismatches > 5 {
				break
			}
		}
	}

	if len(actualLines) != len(goldenLines) {
		t.Fatalf("Line count mismatch. Actual: %d, Golden: %d\nLast few actual:\n%s\nLast few golden:\n%s",
			len(actualLines), len(goldenLines),
			strings.Join(actualLines[max(0, len(actualLines)-3):], "\n"),
			strings.Join(goldenLines[max(0, len(goldenLines)-3):], "\n"))
	}
}
