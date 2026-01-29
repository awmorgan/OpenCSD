package common

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityDebug, "DEBUG"},
		{SeverityInfo, "INFO"},
		{SeverityWarning, "WARNING"},
		{SeverityError, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.severity.String()
			if got != tt.expected {
				t.Errorf("Severity.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewStdLogger(t *testing.T) {
	logger := NewStdLogger(SeverityInfo)
	if logger == nil {
		t.Fatal("NewStdLogger() returned nil")
	}
	if logger.minLevel != SeverityInfo {
		t.Errorf("NewStdLogger() minLevel = %v, want %v", logger.minLevel, SeverityInfo)
	}
}

func TestStdLogger_Log(t *testing.T) {
	var stdout, stderr bytes.Buffer
	logger := NewStdLoggerWithWriter(&stdout, &stderr, SeverityDebug)

	tests := []struct {
		name     string
		severity Severity
		message  string
		checkOut bool // true for stdout, false for stderr
	}{
		{"Debug", SeverityDebug, "debug message", true},
		{"Info", SeverityInfo, "info message", true},
		{"Warning", SeverityWarning, "warning message", true},
		{"Error", SeverityError, "error message", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()

			logger.Log(tt.severity, tt.message)

			var output string
			if tt.checkOut {
				output = stdout.String()
			} else {
				output = stderr.String()
			}

			if !strings.Contains(output, tt.message) {
				t.Errorf("Log output should contain %q, got: %s", tt.message, output)
			}
			if !strings.Contains(output, tt.severity.String()) {
				t.Errorf("Log output should contain severity %q, got: %s", tt.severity.String(), output)
			}
		})
	}
}

func TestStdLogger_Logf(t *testing.T) {
	var stdout, stderr bytes.Buffer
	logger := NewStdLoggerWithWriter(&stdout, &stderr, SeverityInfo)

	logger.Logf(SeverityInfo, "formatted %s %d", "test", 123)

	output := stdout.String()
	if !strings.Contains(output, "formatted test 123") {
		t.Errorf("Logf output should contain formatted message, got: %s", output)
	}
}

func TestStdLogger_Error(t *testing.T) {
	var stdout, stderr bytes.Buffer
	logger := NewStdLoggerWithWriter(&stdout, &stderr, SeverityInfo)

	testErr := errors.New("test error")
	logger.Error(testErr)

	output := stderr.String()
	if !strings.Contains(output, "test error") {
		t.Errorf("Error output should contain error message, got: %s", output)
	}

	// Test with nil error
	stderr.Reset()
	logger.Error(nil)
	if stderr.Len() != 0 {
		t.Errorf("Error(nil) should not log anything, got: %s", stderr.String())
	}
}

func TestStdLogger_ConvenienceMethods(t *testing.T) {
	var stdout, stderr bytes.Buffer
	logger := NewStdLoggerWithWriter(&stdout, &stderr, SeverityDebug)

	tests := []struct {
		name    string
		logFunc func(string)
		message string
		checkFn func(string) bool
	}{
		{
			"Debug",
			logger.Debug,
			"debug test",
			func(s string) bool { return strings.Contains(s, "DEBUG") && strings.Contains(s, "debug test") },
		},
		{
			"Info",
			logger.Info,
			"info test",
			func(s string) bool { return strings.Contains(s, "INFO") && strings.Contains(s, "info test") },
		},
		{
			"Warning",
			logger.Warning,
			"warning test",
			func(s string) bool { return strings.Contains(s, "WARNING") && strings.Contains(s, "warning test") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()

			tt.logFunc(tt.message)

			output := stdout.String()
			if !tt.checkFn(output) {
				t.Errorf("Log output failed check, got: %s", output)
			}
		})
	}
}

func TestStdLogger_MinLevel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	logger := NewStdLoggerWithWriter(&stdout, &stderr, SeverityWarning)

	// Debug and Info should not be logged
	logger.Debug("debug message")
	logger.Info("info message")

	if stdout.Len() != 0 {
		t.Errorf("Debug and Info should not be logged when minLevel is Warning, got: %s", stdout.String())
	}

	// Warning should be logged
	logger.Warning("warning message")

	if !strings.Contains(stdout.String(), "warning message") {
		t.Errorf("Warning should be logged, got: %s", stdout.String())
	}
}

func TestNoOpLogger(t *testing.T) {
	logger := NewNoOpLogger()
	if logger == nil {
		t.Fatal("NewNoOpLogger() returned nil")
	}

	// All these should do nothing and not panic
	logger.Log(SeverityInfo, "test")
	logger.Logf(SeverityInfo, "test %s", "formatted")
	logger.Error(errors.New("test error"))
	logger.Debug("debug")
	logger.Info("info")
	logger.Warning("warning")
}
