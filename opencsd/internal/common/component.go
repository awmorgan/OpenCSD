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

// ComponentAttachNotifier is the notification interface for attachment.
type ComponentAttachNotifier interface {
	// AttachNotify is called whenever a component is attached or detached.
	// numAttached is the number of remaining components attached to the point.
	AttachNotify(numAttached int)
}

// AttachPt is a generic component attachment point.
// T represents the interface type being attached.
type AttachPt[T any] struct {
	enabled     bool
	hasAttached bool
	notifier    ComponentAttachNotifier
	comp        T
}

// NewAttachPt creates a new attachment point.
func NewAttachPt[T any]() *AttachPt[T] {
	return &AttachPt[T]{
		enabled: true,
	}
}

// Attach attaches an interface of type T to the attachment point.
func (a *AttachPt[T]) Attach(comp T) ocsd.Err {
	if a.hasAttached {
		return ocsd.ErrAttachTooMany
	}
	a.comp = comp
	a.hasAttached = true
	if a.notifier != nil {
		a.notifier.AttachNotify(1)
	}
	return ocsd.OK
}

// Detach detaches the current component from the attachment point.
func (a *AttachPt[T]) Detach() ocsd.Err {
	if !a.hasAttached {
		return ocsd.ErrAttachCompNotFound
	}
	var empty T
	a.comp = empty
	a.hasAttached = false
	if a.notifier != nil {
		a.notifier.AttachNotify(0)
	}
	return ocsd.OK
}

// ReplaceFirst detaches any currently attached component and attaches the new one.
func (a *AttachPt[T]) ReplaceFirst(comp T) ocsd.Err {
	if a.hasAttached {
		_ = a.Detach()
	}
	return a.Attach(comp)
}

// DetachAll detaches all components.
func (a *AttachPt[T]) DetachAll() {
	if a.hasAttached {
		_ = a.Detach()
	}
}

// First returns the current attached interface.
// Note: The caller should verify HasAttached() or HasAttachedAndEnabled() before using.
func (a *AttachPt[T]) First() T {
	if !a.enabled {
		var empty T
		return empty
	}
	return a.comp
}

// SetNotifier sets the notification interface.
func (a *AttachPt[T]) SetNotifier(notifier ComponentAttachNotifier) {
	a.notifier = notifier
}

// Enabled returns true if the attachment point is enabled.
func (a *AttachPt[T]) Enabled() bool {
	return a.enabled
}

// SetEnabled sets the enabled state.
func (a *AttachPt[T]) SetEnabled(enable bool) {
	a.enabled = enable
}

// HasAttached returns true if there is an attached interface.
func (a *AttachPt[T]) HasAttached() bool {
	return a.hasAttached
}

// HasAttachedAndEnabled returns true if there is an attachment and it is enabled.
func (a *AttachPt[T]) HasAttachedAndEnabled() bool {
	return a.hasAttached && a.enabled
}

// TraceComponent is the base struct for all decode components in the library.
// It provides error logging attachment, component naming, and operational mode handling.
type TraceComponent struct {
	name             string
	opFlags          uint32
	supportedOpFlags uint32
	errorLogger      AttachPt[TraceErrorLog]
	errVerbosity     ocsd.ErrSeverity
	assocComp        *TraceComponent
}

// InitTraceComponent initializes a TraceComponent. This is favored over a constructor
// so it can be safely embedded and initialized in place.
func (tc *TraceComponent) InitTraceComponent(name string) {
	tc.name = name
	tc.errVerbosity = ocsd.ErrSevError
	tc.errorLogger.enabled = true
}

// ComponentName returns the component's name.
func (tc *TraceComponent) ComponentName() string {
	return tc.name
}

// SetComponentName sets the component's name.
func (tc *TraceComponent) SetComponentName(name string) {
	tc.name = name
}

// ErrorLogAttachPt returns the error logger attachment point.
func (tc *TraceComponent) ErrorLogAttachPt() *AttachPt[TraceErrorLog] {
	return &tc.errorLogger
}

// SetComponentOpMode sets the operational mode for the component.
func (tc *TraceComponent) SetComponentOpMode(opFlags uint32) ocsd.Err {
	// If flags contain unsupported flags, return an error.
	if (opFlags & ^tc.supportedOpFlags) != 0 {
		return ocsd.ErrInvalidParamVal
	}
	tc.opFlags = opFlags
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

// SetSupportedOpModes sets the supported operational mode flags (used by derived structs).
func (tc *TraceComponent) SetSupportedOpModes(flags uint32) {
	tc.supportedOpFlags = flags
}

// SetAssocComponent sets the associated trace component.
func (tc *TraceComponent) SetAssocComponent(assocComp *TraceComponent) {
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
	if tc.errorLogger.HasAttachedAndEnabled() {
		// Create an error message directly or pass it to error logger.
		// Since our TraceErrorLog interface takes severity and message, we pass those.
		tc.errorLogger.First().LogError(err.Sev, err.Error())
	}
}

// LogMessage logs a message if the level matches the verbosity and a logger is attached.
func (tc *TraceComponent) LogMessage(filterLevel ocsd.ErrSeverity, msg string) {
	if filterLevel <= tc.errVerbosity && tc.errorLogger.HasAttachedAndEnabled() {
		tc.errorLogger.First().LogMessage(filterLevel, msg)
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

// SetErrorLogLevel sets the verbosity of error logging.
func (tc *TraceComponent) SetErrorLogLevel(level ocsd.ErrSeverity) {
	tc.errVerbosity = level
}
