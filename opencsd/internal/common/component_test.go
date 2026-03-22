package common

import (
	"testing"

	"opencsd/internal/ocsd"
)

// mockErrorLog is a mock implementation of TraceErrorLog
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

func TestComponentRuntimeViaPktProcI(t *testing.T) {
	tc := &PktProcI{}
	tc.Init("TestComp", nil)

	if tc.ErrorLogLevel() != ocsd.ErrSevNone {
		t.Errorf("expected default error log level to be ErrSevNone")
	}

	if tc.ComponentName() != "TestComp" {
		t.Errorf("expected name TestComp, got %s", tc.ComponentName())
	}

	tc.Init("NewName", nil)
	if tc.ComponentName() != "NewName" {
		t.Errorf("expected NewName")
	}

	tc.ConfigureSupportedOpModes(0x0F)
	err := tc.ConfigureComponentOpMode(0x01)
	if err != ocsd.OK {
		t.Errorf("expected OK")
	}
	if tc.ComponentOpMode() != 0x01 {
		t.Errorf("expected op mode 0x01")
	}

	err = tc.ConfigureComponentOpMode(0x10)
	if err != ocsd.OK {
		t.Errorf("expected OK for unsupported-flag mask behavior")
	}
	if tc.ComponentOpMode() != 0x00 {
		t.Errorf("expected unsupported flags to be masked out")
	}

	// Test logging
	logger := &mockErrorLog{}
	if err := tc.AttachErrorLogger(logger); err != ocsd.OK {
		t.Fatalf("AttachErrorLogger failed: %v", err)
	}
	if err := tc.AttachErrorLogger(&mockErrorLog{}); err != ocsd.ErrAttachTooMany {
		t.Fatalf("second AttachErrorLogger should fail with ErrAttachTooMany, got: %v", err)
	}
	tc.ConfigureErrorLogLevel(ocsd.ErrSevInfo)

	tc.LogMessage(ocsd.ErrSevWarn, "A warning")
	if logger.lastMsg != "A warning" || logger.lastMsgSev != ocsd.ErrSevWarn {
		t.Errorf("log message was not passed to logger correctly")
	}

	// This shouldn't log because severity is none
	tc.ConfigureErrorLogLevel(ocsd.ErrSevNone)
	tc.LogMessage(ocsd.ErrSevError, "Should not log")
	if logger.lastMsg == "Should not log" {
		t.Errorf("expected message to be filtered")
	}

	tc.ConfigureErrorLogLevel(ocsd.ErrSevError)
	tc.LogDefMessage("Default error")
	if logger.lastMsg != "Default error" || logger.lastMsgSev != ocsd.ErrSevError {
		t.Errorf("default log message failed")
	}

	tc.LogError(Errorf(ocsd.ErrSevError, ocsd.ErrInvalidID, "test error"))
	// Depending on your ocsd.Error format, we just check if it hit the logger
	if logger.lastErrSev != ocsd.ErrSevError {
		t.Errorf("log error failed to pass severity")
	}
	if logger.lastErrMsg == "" {
		t.Errorf("log error failed to pass message")
	}

	if err := tc.DetachErrorLogger(); err != ocsd.OK {
		t.Fatalf("DetachErrorLogger should succeed, got %v", err)
	}
	if err := tc.DetachErrorLogger(); err != ocsd.ErrAttachCompNotFound {
		t.Fatalf("second DetachErrorLogger should fail with ErrAttachCompNotFound, got %v", err)
	}
}
