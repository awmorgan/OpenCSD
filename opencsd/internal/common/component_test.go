package common

import (
	"testing"

	"opencsd/internal/ocsd"
)

// mockErrorLog is a mock implementation of ocsd.Logger
type mockErrorLog struct {
	lastErrSev ocsd.ErrSeverity
	lastErrMsg string
	lastMsgSev ocsd.ErrSeverity
	lastMsg    string
}

func (m *mockErrorLog) LogError(filterLevel ocsd.ErrSeverity, err error) {
	m.lastErrSev = filterLevel
	if err != nil {
		m.lastErrMsg = err.Error()
	}
}

func (m *mockErrorLog) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	m.lastMsgSev = filterLevel
	m.lastMsg = msg
}

func TestComponentRuntimeViaDecoderBase(t *testing.T) {
	b := &DecoderBase{}
	b.Init("TestComp", nil)

	if b.ErrVerbosity != ocsd.ErrSevNone {
		t.Errorf("expected default error log level ErrSevNone, got %v", b.ErrVerbosity)
	}
	if b.Name != "TestComp" {
		t.Errorf("expected name TestComp, got %s", b.Name)
	}

	b.ConfigureSupportedOpModes(0x0F)
	err := b.SetComponentOpMode(0x01)
	if err != nil {
		t.Errorf("expected OK, got %v", err)
	}
	if b.ComponentOpMode() != 0x01 {
		t.Errorf("expected op mode 0x01, got 0x%x", b.ComponentOpMode())
	}

	err = b.SetComponentOpMode(0x10)
	if err != nil {
		t.Errorf("expected OK for unsupported-flag mask behaviour, got %v", err)
	}
	if b.ComponentOpMode() != 0x00 {
		t.Errorf("expected unsupported flags to be masked out, got 0x%x", b.ComponentOpMode())
	}

	logger := &mockErrorLog{}
	b.Logger = logger
	b.ErrVerbosity = ocsd.ErrSevInfo

	b.LogMessage(ocsd.ErrSevWarn, "A warning")
	if logger.lastMsg != "A warning" || logger.lastMsgSev != ocsd.ErrSevWarn {
		t.Errorf("log message was not passed to logger correctly")
	}

	// Should not log if severity is too high
	b.ErrVerbosity = ocsd.ErrSevNone
	b.LogMessage(ocsd.ErrSevError, "Should not log")
	if logger.lastMsg == "Should not log" {
		t.Errorf("expected message to be filtered out")
	}

	b.ErrVerbosity = ocsd.ErrSevError
	b.LogError(ocsd.ErrSevError, ocsd.ErrInvalidID)
	if logger.lastErrSev != ocsd.ErrSevError {
		t.Errorf("log error failed to pass severity")
	}
	if logger.lastErrMsg == "" {
		t.Errorf("log error failed to pass message")
	}
}
