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

func (m *mockErrorLog) LogError(filterLevel ocsd.ErrSeverity, msg string) {
	m.lastErrSev = filterLevel
	m.lastErrMsg = msg
}

func (m *mockErrorLog) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	m.lastMsgSev = filterLevel
	m.lastMsg = msg
}

type mockNotifier struct {
	numAttached int
	called      bool
}

func (m *mockNotifier) AttachNotify(numAttached int) {
	m.numAttached = numAttached
	m.called = true
}

func TestAttachPt(t *testing.T) {
	// Test basic attach
	pt := NewAttachPt[TraceErrorLog]()
	if pt.HasAttached() {
		t.Errorf("expected no attachment initially")
	}

	logger := &mockErrorLog{}
	err := pt.Attach(logger)
	if err != ocsd.OK {
		t.Errorf("expected OK, got %v", err)
	}
	if !pt.HasAttached() {
		t.Errorf("expected attachment")
	}
	if !pt.IsActive() {
		t.Errorf("expected attachment and enabled")
	}

	// Test attaching again (should fail)
	logger2 := &mockErrorLog{}
	err = pt.Attach(logger2)
	if err != ocsd.ErrAttachTooMany {
		t.Errorf("expected ErrAttachTooMany, got %v", err)
	}

	// Test detach
	err = pt.Detach()
	if err != ocsd.OK {
		t.Errorf("expected OK, got %v", err)
	}
	if pt.HasAttached() {
		t.Errorf("expected no attachment after detach")
	}

	// Test detach when empty
	err = pt.Detach()
	if err != ocsd.ErrAttachCompNotFound {
		t.Errorf("expected ErrAttachCompNotFound, got %v", err)
	}

	// Test replace first
	err = pt.ReplaceFirst(logger)
	if err != ocsd.OK {
		t.Errorf("expected OK, got %v", err)
	}
	err = pt.ReplaceFirst(logger2)
	if err != ocsd.OK {
		t.Errorf("expected OK, got %v", err)
	}
	if pt.First() != logger2 {
		t.Errorf("expected logger2 to be attached")
	}

	// Test notifier
	notifier := &mockNotifier{}
	pt.SetNotifier(notifier)

	pt.DetachAll()
	if notifier.called && notifier.numAttached != 0 {
		t.Errorf("expected numAttached 0")
	}

	notifier.called = false
	pt.DetachAll()
	if !notifier.called || notifier.numAttached != 0 {
		t.Errorf("expected detach-all notification when already empty")
	}

	notifier.called = false
	pt.Attach(logger)
	if !notifier.called || notifier.numAttached != 1 {
		t.Errorf("expected numAttached 1")
	}

	if pt.NumAttached() != 1 {
		t.Errorf("expected NumAttached 1")
	}

	err = pt.ReplaceFirst(nil)
	if err != ocsd.OK {
		t.Errorf("expected OK replacing with nil")
	}
	if pt.HasAttached() {
		t.Errorf("expected no attachment after ReplaceFirst(nil)")
	}
	if pt.NumAttached() != 0 {
		t.Errorf("expected NumAttached 0 after ReplaceFirst(nil)")
	}

	// Test disable
	pt.SetEnabled(false)
	if pt.IsActive() {
		t.Errorf("expected IsActive to be false")
	}
	if pt.First() != nil {
		t.Errorf("expected nil First() when disabled")
	}
}

func TestTraceComponent(t *testing.T) {
	tc := &TraceComponent{}
	tc.InitTraceComponent("TestComp")

	if tc.ErrorLogLevel() != ocsd.ErrSevNone {
		t.Errorf("expected default error log level to be ErrSevNone")
	}

	if tc.ComponentName() != "TestComp" {
		t.Errorf("expected name TestComp, got %s", tc.ComponentName())
	}

	tc.SetComponentName("NewName")
	if tc.ComponentName() != "NewName" {
		t.Errorf("expected NewName")
	}

	tc.SetSupportedOpModes(0x0F)
	err := tc.SetComponentOpMode(0x01)
	if err != ocsd.OK {
		t.Errorf("expected OK")
	}
	if tc.ComponentOpMode() != 0x01 {
		t.Errorf("expected op mode 0x01")
	}

	err = tc.SetComponentOpMode(0x10)
	if err != ocsd.OK {
		t.Errorf("expected OK for unsupported-flag mask behavior")
	}
	if tc.ComponentOpMode() != 0x00 {
		t.Errorf("expected unsupported flags to be masked out")
	}

	assoc := &TraceComponent{}
	tc.SetAssocComponent(assoc)
	if tc.AssocComponent() != assoc {
		t.Errorf("expected associated component to be set")
	}

	// Test logging
	logger := &mockErrorLog{}
	if err := tc.AttachErrorLogger(logger); err != ocsd.OK {
		t.Fatalf("AttachErrorLogger failed: %v", err)
	}
	tc.SetErrorLogLevel(ocsd.ErrSevInfo)

	tc.LogMessage(ocsd.ErrSevWarn, "A warning")
	if logger.lastMsg != "A warning" || logger.lastMsgSev != ocsd.ErrSevWarn {
		t.Errorf("log message was not passed to logger correctly")
	}

	// This shouldn't log because severity is none
	tc.SetErrorLogLevel(ocsd.ErrSevNone)
	tc.LogMessage(ocsd.ErrSevError, "Should not log")
	if logger.lastMsg == "Should not log" {
		t.Errorf("expected message to be filtered")
	}

	tc.SetErrorLogLevel(ocsd.ErrSevError)
	tc.LogDefMessage("Default error")
	if logger.lastMsg != "Default error" || logger.lastMsgSev != ocsd.ErrSevError {
		t.Errorf("default log message failed")
	}

	tc.LogError(NewErrorMsg(ocsd.ErrSevError, ocsd.ErrInvalidID, "test error"))
	// Depending on your ocsd.Error format, we just check if it hit the logger
	if logger.lastErrSev != ocsd.ErrSevError {
		t.Errorf("log error failed to pass severity")
	}
	if logger.lastErrMsg == "" {
		t.Errorf("log error failed to pass message")
	}
}
