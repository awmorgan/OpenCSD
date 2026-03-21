package dcdtree

import (
	"errors"
	"fmt"
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
	"sort"
	"sync"
)

var (
	// ErrDecoderRegistration indicates decoder registration failed.
	ErrDecoderRegistration = errors.New("decoder registration failed")
	// ErrDecoderManagerNotFound indicates decoder manager lookup failed.
	ErrDecoderManagerNotFound = errors.New("decoder manager not found")
)

// DecoderRegister manages decoder protocol factories for the library.
type DecoderRegister struct {
	mu           sync.RWMutex
	decoderMngrs map[string]interfaces.DecoderMngr
	typedMngrs   map[ocsd.TraceProtocol]interfaces.DecoderMngr
	nextCustomID ocsd.TraceProtocol
}

var defaultRegister = NewBuiltinDecoderRegister()

// DefaultDecoderRegister returns the package-level registry populated with built-in decoders.
func DefaultDecoderRegister() *DecoderRegister {
	return defaultRegister
}

// NewDecoderRegister creates a new decoder registry instance.
func NewDecoderRegister() *DecoderRegister {
	return &DecoderRegister{
		decoderMngrs: make(map[string]interfaces.DecoderMngr),
		typedMngrs:   make(map[ocsd.TraceProtocol]interfaces.DecoderMngr),
		nextCustomID: ocsd.ProtocolCustom0,
	}
}

// NewBuiltinDecoderRegister creates a registry populated with the standard built-in decoders.
func NewBuiltinDecoderRegister() *DecoderRegister {
	reg := NewDecoderRegister()
	registerBuiltinDecoders(reg)
	return reg
}

// RegisterDecoderTypeByName registers a decoder manager factory under a specific name.
func (r *DecoderRegister) RegisterDecoderTypeByName(name string, mngr interfaces.DecoderMngr) ocsd.Err {
	if mngr == nil {
		return ocsd.ErrInvalidParamVal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.decoderMngrs[name]; exists {
		return ocsd.ErrDcdregNameRepeat
	}
	r.decoderMngrs[name] = mngr
	if mngr.ProtocolType() != ocsd.ProtocolUnknown {
		if _, exists := r.typedMngrs[mngr.ProtocolType()]; exists {
			return ocsd.OK
		}
		r.typedMngrs[mngr.ProtocolType()] = mngr
	}
	return ocsd.OK
}

// Register registers a decoder manager and returns a Go error.
func (r *DecoderRegister) Register(name string, mngr interfaces.DecoderMngr) error {
	err := r.RegisterDecoderTypeByName(name, mngr)
	if err == ocsd.OK {
		return nil
	}
	return fmt.Errorf("%w: %q (ocsd err %d)", ErrDecoderRegistration, name, uint32(err))
}

// DecoderMngrByName retrieves a decoder factory by its registered name string.
func (r *DecoderRegister) DecoderMngrByName(name string) (interfaces.DecoderMngr, ocsd.Err) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if mngr, exists := r.decoderMngrs[name]; exists {
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregNameUnknown
}

// DecoderManagerByName retrieves a decoder manager by name and returns a Go error.
func (r *DecoderRegister) DecoderManagerByName(name string) (interfaces.DecoderMngr, error) {
	mngr, err := r.DecoderMngrByName(name)
	if err == ocsd.OK {
		return mngr, nil
	}
	return nil, fmt.Errorf("%w: %q (ocsd err %d)", ErrDecoderManagerNotFound, name, uint32(err))
}

// DecoderMngrByType retrieves a decoder factory by its protocol enum value.
func (r *DecoderRegister) DecoderMngrByType(dcdType ocsd.TraceProtocol) (interfaces.DecoderMngr, ocsd.Err) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if mngr, exists := r.typedMngrs[dcdType]; exists {
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregTypeUnknown
}

// DecoderManagerByType retrieves a decoder manager by protocol and returns a Go error.
func (r *DecoderRegister) DecoderManagerByType(dcdType ocsd.TraceProtocol) (interfaces.DecoderMngr, error) {
	mngr, err := r.DecoderMngrByType(dcdType)
	if err == ocsd.OK {
		return mngr, nil
	}
	return nil, fmt.Errorf("%w: protocol %v (ocsd err %d)", ErrDecoderManagerNotFound, dcdType, uint32(err))
}

// NextCustomProtocolID allocates the next custom protocol ID.
func (r *DecoderRegister) NextCustomProtocolID() ocsd.TraceProtocol {
	r.mu.Lock()
	defer r.mu.Unlock()
	ret := r.nextCustomID
	if r.nextCustomID < ocsd.ProtocolEnd {
		r.nextCustomID++
	}
	return ret
}

// ReleaseLastCustomProtocolID releases the most recently allocated custom protocol ID.
func (r *DecoderRegister) ReleaseLastCustomProtocolID() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nextCustomID > ocsd.ProtocolCustom0 {
		r.nextCustomID--
	}
}

// IsRegisteredDecoder checks whether a decoder is registered by name.
func (r *DecoderRegister) IsRegisteredDecoder(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.decoderMngrs[name]
	return exists
}

// IsRegisteredDecoderType checks whether a decoder manager is registered for a protocol.
func (r *DecoderRegister) IsRegisteredDecoderType(dcdType ocsd.TraceProtocol) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.typedMngrs[dcdType]
	return exists
}

// Names returns a sorted snapshot of all registered decoder names.
func (r *DecoderRegister) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.namesLocked()
}

func (r *DecoderRegister) namesLocked() []string {
	names := make([]string, 0, len(r.decoderMngrs))
	for name := range r.decoderMngrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
