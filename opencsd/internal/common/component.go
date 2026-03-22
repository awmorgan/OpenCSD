package common

import (
	"opencsd/internal/ocsd"
)

// TraceErrorLog represents ITraceErrorLog.
// Interface to the target environment error logging functionality.
type TraceErrorLog interface {
	// LogError logs an error.
	LogError(filterLevel ocsd.ErrSeverity, msg string)
	// LogMessage logs a standard message.
	LogMessage(filterLevel ocsd.ErrSeverity, msg string)
}

// It provides error logging attachment, component naming, and operational mode handling.
type TraceComponent struct {
	name             string
	opFlags          uint32
	supportedOpFlags uint32
	errorLogger      TraceErrorLog
	errLogHandle     ocsd.HandleErrLog
	errVerbosity     ocsd.ErrSeverity
	assocComp        *TraceComponent
}

// ConfigureTraceComponent initializes a TraceComponent. This is favored over a constructor
// so it can be safely embedded and initialized in place.
func (tc *TraceComponent) ConfigureTraceComponent(name string) {
	tc.name = name
	tc.errLogHandle = ocsd.HandleErrLog(ocsd.InvalidHandle)
	tc.errVerbosity = ocsd.ErrSevNone
	tc.errorLogger = nil
}

// ComponentName returns the component's name.
func (tc *TraceComponent) ComponentName() string {
	return tc.name
}

// AttachErrorLogger attaches an error logger implementation.
func (tc *TraceComponent) AttachErrorLogger(logger TraceErrorLog) ocsd.Err {
	if tc.errorLogger != nil {
		return ocsd.ErrAttachTooMany
	}
	tc.errorLogger = logger
	if logger != nil {
		tc.errLogHandle = 0
	}
	return ocsd.OK
}

// DetachErrorLogger detaches the currently attached error logger.
func (tc *TraceComponent) DetachErrorLogger() ocsd.Err {
	if tc.errorLogger == nil {
		return ocsd.ErrAttachCompNotFound
	}
	tc.errorLogger = nil
	tc.errLogHandle = ocsd.HandleErrLog(ocsd.InvalidHandle)
	return ocsd.OK
}

// ConfigureComponentOpMode sets the operational mode for the component.
func (tc *TraceComponent) ConfigureComponentOpMode(opFlags uint32) ocsd.Err {
	tc.opFlags = opFlags & tc.supportedOpFlags
	return ocsd.OK
}

// ComponentOpMode returns the current operational mode flags values.
func (tc *TraceComponent) ComponentOpMode() uint32 {
	return tc.opFlags
}

// SupportedOpModes gets the supported operational mode flags for this component.
func (tc *TraceComponent) SupportedOpModes() uint32 {
	return tc.supportedOpFlags
}

// ConfigureSupportedOpModes sets the supported operational mode flags (used by derived structs).
func (tc *TraceComponent) ConfigureSupportedOpModes(flags uint32) {
	tc.supportedOpFlags = flags
}

// AttachAssocComponent sets the associated trace component.
func (tc *TraceComponent) AttachAssocComponent(assocComp *TraceComponent) {
	tc.assocComp = assocComp
}

// AssocComponent returns the associated trace component.
func (tc *TraceComponent) AssocComponent() *TraceComponent {
	return tc.assocComp
}

// LogDefMessage logs a message at the default severity on this component.
func (tc *TraceComponent) LogDefMessage(msg string) {
	tc.LogMessage(tc.errVerbosity, msg)
}

// LogError logs an error if an error logger is attached.
func (tc *TraceComponent) LogError(err *Error) {
	if tc.errorLogger != nil && tc.IsLoggingErrorLevel(err.Sev) {
		// Create an error message directly or pass it to error logger.
		// Since our TraceErrorLog interface takes severity and message, we pass those.
		tc.errorLogger.LogError(err.Sev, err.Error())
	}
}

// LogMessage logs a message if the level matches the verbosity and a logger is attached.
func (tc *TraceComponent) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	if filterLevel <= tc.errVerbosity && tc.errorLogger != nil {
		tc.errorLogger.LogMessage(filterLevel, msg)
	}
}

// ErrorLogLevel returns the current error log level.
func (tc *TraceComponent) ErrorLogLevel() ocsd.ErrSeverity {
	return tc.errVerbosity
}

// IsLoggingErrorLevel returns true if the level would be logged.
func (tc *TraceComponent) IsLoggingErrorLevel(level ocsd.ErrSeverity) bool {
	return level <= tc.errVerbosity
}

// ConfigureErrorLogLevel sets the verbosity of error logging.
func (tc *TraceComponent) ConfigureErrorLogLevel(level ocsd.ErrSeverity) {
	tc.errVerbosity = level
}
