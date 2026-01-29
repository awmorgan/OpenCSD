package common

import (
	"fmt"
	"io"
	"log"
	"os"
)

// Severity represents log message severity levels
type Severity int

const (
	SeverityDebug Severity = iota
	SeverityInfo
	SeverityWarning
	SeverityError
)

func (s Severity) String() string {
	switch s {
	case SeverityDebug:
		return "DEBUG"
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger interface defines the logging contract for the decoder
type Logger interface {
	// Log logs a message with the specified severity
	Log(severity Severity, msg string)

	// Logf logs a formatted message with the specified severity
	Logf(severity Severity, format string, args ...interface{})

	// Error logs an error
	Error(err error)

	// Debug logs a debug message
	Debug(msg string)

	// Info logs an info message
	Info(msg string)

	// Warning logs a warning message
	Warning(msg string)
}

// StdLogger implements the Logger interface using Go's standard logger
type StdLogger struct {
	debugLog   *log.Logger
	infoLog    *log.Logger
	warningLog *log.Logger
	errorLog   *log.Logger
	minLevel   Severity
}

// NewStdLogger creates a new standard logger
func NewStdLogger(minLevel Severity) *StdLogger {
	return &StdLogger{
		debugLog:   log.New(os.Stdout, "DEBUG: ", log.Ltime|log.Lshortfile),
		infoLog:    log.New(os.Stdout, "INFO: ", log.Ltime),
		warningLog: log.New(os.Stdout, "WARNING: ", log.Ltime),
		errorLog:   log.New(os.Stderr, "ERROR: ", log.Ltime|log.Lshortfile),
		minLevel:   minLevel,
	}
}

// NewStdLoggerWithWriter creates a new standard logger with custom writers
func NewStdLoggerWithWriter(stdout, stderr io.Writer, minLevel Severity) *StdLogger {
	return &StdLogger{
		debugLog:   log.New(stdout, "DEBUG: ", log.Ltime|log.Lshortfile),
		infoLog:    log.New(stdout, "INFO: ", log.Ltime),
		warningLog: log.New(stdout, "WARNING: ", log.Ltime),
		errorLog:   log.New(stderr, "ERROR: ", log.Ltime|log.Lshortfile),
		minLevel:   minLevel,
	}
}

// Log logs a message with the specified severity
func (l *StdLogger) Log(severity Severity, msg string) {
	if severity < l.minLevel {
		return
	}

	switch severity {
	case SeverityDebug:
		l.debugLog.Output(2, msg)
	case SeverityInfo:
		l.infoLog.Output(2, msg)
	case SeverityWarning:
		l.warningLog.Output(2, msg)
	case SeverityError:
		l.errorLog.Output(2, msg)
	}
}

// Logf logs a formatted message with the specified severity
func (l *StdLogger) Logf(severity Severity, format string, args ...interface{}) {
	l.Log(severity, fmt.Sprintf(format, args...))
}

// Error logs an error
func (l *StdLogger) Error(err error) {
	if err != nil {
		l.Log(SeverityError, err.Error())
	}
}

// Debug logs a debug message
func (l *StdLogger) Debug(msg string) {
	l.Log(SeverityDebug, msg)
}

// Info logs an info message
func (l *StdLogger) Info(msg string) {
	l.Log(SeverityInfo, msg)
}

// Warning logs a warning message
func (l *StdLogger) Warning(msg string) {
	l.Log(SeverityWarning, msg)
}

// NoOpLogger is a logger that doesn't log anything
type NoOpLogger struct{}

// NewNoOpLogger creates a new no-op logger
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

// Log does nothing
func (l *NoOpLogger) Log(severity Severity, msg string) {}

// Logf does nothing
func (l *NoOpLogger) Logf(severity Severity, format string, args ...interface{}) {}

// Error does nothing
func (l *NoOpLogger) Error(err error) {}

// Debug does nothing
func (l *NoOpLogger) Debug(msg string) {}

// Info does nothing
func (l *NoOpLogger) Info(msg string) {}

// Warning does nothing
func (l *NoOpLogger) Warning(msg string) {}
