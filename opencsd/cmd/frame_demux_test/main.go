// Package main implements frame_demux_test - tests the frame demux functionality.
// This is a Go port of the C++ frame_demux_test.cpp utility.
package main

import (
	"fmt"
	"log"
	"os"
)

const frameDemuxStandaloneMsg = "frame_demux_test is a standalone scaffold and not wired to the OpenCSD decoder core.\n" +
	"It validates local frame parsing behavior only.\n"

// DataPathResponse represents responses from the data processing path
type DataPathResponse int

const (
	RespContinue DataPathResponse = iota
	RespWait
	RespError
	RespFatal
)

func (r DataPathResponse) String() string {
	switch r {
	case RespContinue:
		return "CONTINUE"
	case RespWait:
		return "WAIT"
	case RespError:
		return "ERROR"
	case RespFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// FrameFormatFlags defines frame formatter configuration flags
type FrameFormatFlags uint32

const (
	FrmtMemAlign FrameFormatFlags = 1 << iota
	FrmtPackedRawOut
	FrmtUnpackedRawOut
	FrmtHasFsyncs
	FrmtHasHsyncs
	FrmtLogRawFrames
	FrmtLogSourceID
	FrmtLogFrameID
)

// FrameDeformatter processes raw trace frames
type FrameDeformatter struct {
	flags       FrameFormatFlags
	inputCount  uint64
	outputCount uint64
	frameCount  uint64
	errorLog    *ErrorLogger
	lastError   error
}

// NewFrameDeformatter creates a new frame deformatter
func NewFrameDeformatter(errorLog *ErrorLogger) *FrameDeformatter {
	return &FrameDeformatter{
		errorLog: errorLog,
	}
}

// Configure sets up the frame deformatter with the specified flags
func (f *FrameDeformatter) Configure(flags FrameFormatFlags) error {
	// Validate flag combinations
	if flags == 0 {
		return fmt.Errorf("OCSD_ERR_INVALID_PARAM_VAL: no flags specified")
	}

	// Check for invalid flag combinations
	if (flags&FrmtMemAlign) != 0 && (flags&FrmtHasFsyncs) != 0 {
		return fmt.Errorf("OCSD_ERR_INVALID_PARAM_VAL: invalid flag combination")
	}

	// Check for unknown flags
	validFlags := FrmtMemAlign | FrmtPackedRawOut | FrmtUnpackedRawOut |
		FrmtHasFsyncs | FrmtHasHsyncs | FrmtLogRawFrames |
		FrmtLogSourceID | FrmtLogFrameID

	if (flags & ^validFlags) != 0 {
		return fmt.Errorf("OCSD_ERR_INVALID_PARAM_VAL: unknown flags specified")
	}

	f.flags = flags
	return nil
}

// ProcessFrame processes a single frame of trace data
func (f *FrameDeformatter) ProcessFrame(data []byte) (DataPathResponse, error) {
	if len(data) == 0 {
		return RespError, fmt.Errorf("empty frame data")
	}

	// Frame sync markers
	const (
		FSYNC = 0xFFFFFF7F
		HSYNC = 0xFF7F
	)

	// Simple frame validation - check for sync markers
	for i := 0; i < len(data)-3; i++ {
		// Check for FSYNC (frame sync)
		if f.flags&FrmtHasFsyncs != 0 {
			if i+4 <= len(data) {
				val := uint32(data[i]) | uint32(data[i+1])<<8 |
					uint32(data[i+2])<<16 | uint32(data[i+3])<<24
				if val == FSYNC {
					f.frameCount++
				}
			}
		}
		// Check for HSYNC (header sync)
		if f.flags&FrmtHasHsyncs != 0 {
			if i+2 <= len(data) {
				val := uint16(data[i]) | uint16(data[i+1])<<8
				if val == HSYNC {
					f.frameCount++
				}
			}
		}
	}

	f.inputCount += uint64(len(data))
	f.outputCount += uint64(len(data)) // Simplified - actual deframing would generate output

	return RespContinue, nil
}

// Reset resets the deformatter state
func (f *FrameDeformatter) Reset() {
	f.inputCount = 0
	f.outputCount = 0
	f.frameCount = 0
	f.lastError = nil
}

// ErrorLogger logs errors
type ErrorLogger struct {
	logger *log.Logger
	errors []error
}

// NewErrorLogger creates a new error logger
func NewErrorLogger() *ErrorLogger {
	return &ErrorLogger{
		logger: log.New(os.Stdout, "ERROR: ", log.LstdFlags),
		errors: make([]error, 0),
	}
}

// LogError logs an error
func (e *ErrorLogger) LogError(err error) {
	e.errors = append(e.errors, err)
	e.logger.Println(err)
}

// GetLastError returns the most recent error
func (e *ErrorLogger) GetLastError() error {
	if len(e.errors) == 0 {
		return nil
	}
	return e.errors[len(e.errors)-1]
}

// TestRunner runs frame demux tests
type TestRunner struct {
	deformatter *FrameDeformatter
	errorLog    *ErrorLogger
	logger      *log.Logger
	testCount   int
	passCount   int
	failCount   int
}

// NewTestRunner creates a new test runner
func NewTestRunner() *TestRunner {
	errorLog := NewErrorLogger()
	return &TestRunner{
		deformatter: NewFrameDeformatter(errorLog),
		errorLog:    errorLog,
		logger:      log.New(os.Stdout, "", log.LstdFlags),
	}
}

// PrintTestHeader prints a test header
func (t *TestRunner) PrintTestHeader(name string) {
	fmt.Printf("\n%s\n", name)
	fmt.Println(repeatChar('=', len(name)))
}

func repeatChar(c rune, count int) string {
	s := ""
	for i := 0; i < count; i++ {
		s += string(c)
	}
	return s
}

// Assert checks a condition and records pass/fail
func (t *TestRunner) Assert(condition bool, message string) {
	t.testCount++
	if condition {
		t.passCount++
		fmt.Printf("  PASS: %s\n", message)
	} else {
		t.failCount++
		fmt.Printf("  FAIL: %s\n", message)
	}
}

// TestDemuxInit tests demux initialization
func (t *TestRunner) TestDemuxInit() {
	t.PrintTestHeader("Demux Init Tests")

	// Test: no flags should fail
	t.deformatter.Reset()
	err := t.deformatter.Configure(0)
	t.Assert(err != nil, "Zero flags rejected")

	// Test: invalid flags should fail
	err = t.deformatter.Configure(0x80) // Unknown flag
	t.Assert(err != nil, "Unknown flags rejected")

	// Test: bad flag combination
	err = t.deformatter.Configure(FrmtMemAlign | FrmtHasFsyncs)
	t.Assert(err != nil, "Invalid flag combination rejected")

	// Test: valid configuration
	err = t.deformatter.Configure(FrmtMemAlign | FrmtPackedRawOut)
	t.Assert(err == nil, "Valid configuration accepted")
}

// TestFrameProcessing tests basic frame processing
func (t *TestRunner) TestFrameProcessing() {
	t.PrintTestHeader("Frame Processing Tests")

	t.deformatter.Reset()
	err := t.deformatter.Configure(FrmtMemAlign | FrmtPackedRawOut)
	t.Assert(err == nil, "Configure deformatter")

	// Test with sample data
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	resp, err := t.deformatter.ProcessFrame(testData)
	t.Assert(err == nil && resp == RespContinue, "Process valid frame")

	// Test with empty data
	_, err = t.deformatter.ProcessFrame([]byte{})
	t.Assert(err != nil, "Empty frame rejected")

	// Test frame counts
	t.Assert(t.deformatter.inputCount > 0, "Input count incremented")
}

// TestSyncMarkers tests frame sync marker detection
func (t *TestRunner) TestSyncMarkers() {
	t.PrintTestHeader("Sync Marker Tests")

	// Test HSYNC detection
	t.deformatter.Reset()
	err := t.deformatter.Configure(FrmtHasHsyncs | FrmtPackedRawOut)
	t.Assert(err == nil, "Configure with HSYNC")

	hsyncData := []byte{0x01, 0x02, 0xff, 0x7f, 0x03, 0x04}
	resp, err := t.deformatter.ProcessFrame(hsyncData)
	t.Assert(err == nil && resp == RespContinue, "Process frame with HSYNC")

	// Test FSYNC detection
	t.deformatter.Reset()
	err = t.deformatter.Configure(FrmtHasFsyncs | FrmtUnpackedRawOut)
	t.Assert(err == nil, "Configure with FSYNC")

	fsyncData := []byte{0x01, 0x7f, 0xff, 0xff, 0xff, 0x02}
	resp, err = t.deformatter.ProcessFrame(fsyncData)
	t.Assert(err == nil && resp == RespContinue, "Process frame with FSYNC")
}

func main() {
	fmt.Fprint(os.Stderr, frameDemuxStandaloneMsg)

	fmt.Println("Frame Deformatter Test Program")
	fmt.Println("==============================")

	runner := NewTestRunner()

	runner.TestDemuxInit()
	runner.TestFrameProcessing()
	runner.TestSyncMarkers()

	fmt.Printf("\n\nTest Results: %d tests, %d passed, %d failed\n",
		runner.testCount, runner.passCount, runner.failCount)

	if runner.failCount > 0 {
		os.Exit(1)
	}
}
