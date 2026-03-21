package dcdtree

import (
	"errors"
	"fmt"

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
	mu              sync.RWMutex
	decoderManagers map[string]ocsd.DecoderManager
	typedManagers   map[ocsd.TraceProtocol]ocsd.DecoderManager
	nextCustomID    ocsd.TraceProtocol
}

// NewDecoderRegister creates a new decoder registry instance.
func NewDecoderRegister() *DecoderRegister {
	return &DecoderRegister{
		decoderManagers: make(map[string]ocsd.DecoderManager),
		typedManagers:   make(map[ocsd.TraceProtocol]ocsd.DecoderManager),
		nextCustomID:    ocsd.ProtocolCustom0,
	}
}

// NewBuiltinDecoderRegister creates a registry populated with the standard built-in decoders.
func NewBuiltinDecoderRegister() *DecoderRegister {
	reg := NewDecoderRegister()
	registerBuiltinDecoders(reg)
	return reg
}

func (r *DecoderRegister) registerDecoderManagerByNameStatus(name string, mngr ocsd.DecoderManager) ocsd.Err {
	if mngr == nil {
		return ocsd.ErrInvalidParamVal
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.decoderManagers[name]; exists {
		return ocsd.ErrDcdregNameRepeat
	}
	r.decoderManagers[name] = mngr
	if mngr.ProtocolType() != ocsd.ProtocolUnknown {
		if _, exists := r.typedManagers[mngr.ProtocolType()]; exists {
			return ocsd.OK
		}
		r.typedManagers[mngr.ProtocolType()] = mngr
	}
	return ocsd.OK
}

// RegisterDecoderManagerByName registers a decoder manager factory under a specific name.
func (r *DecoderRegister) RegisterDecoderManagerByName(name string, mngr ocsd.DecoderManager) error {
	err := r.registerDecoderManagerByNameStatus(name, mngr)
	if err == ocsd.OK {
		return nil
	}
	return fmt.Errorf("%w: %q (ocsd err %d)", ErrDecoderRegistration, name, uint32(err))
}

// Register registers a decoder manager and returns a Go error.
func (r *DecoderRegister) Register(name string, mngr ocsd.DecoderManager) error {
	return r.RegisterDecoderManagerByName(name, mngr)
}

func (r *DecoderRegister) decoderManagerByNameStatus(name string) (ocsd.DecoderManager, ocsd.Err) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if mngr, exists := r.decoderManagers[name]; exists {
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregNameUnknown
}

// DecoderManagerByName retrieves a decoder manager by name and returns a Go error.
func (r *DecoderRegister) DecoderManagerByName(name string) (ocsd.DecoderManager, error) {
	mngr, err := r.decoderManagerByNameStatus(name)
	if err == ocsd.OK {
		return mngr, nil
	}
	return nil, fmt.Errorf("%w: %q (ocsd err %d)", ErrDecoderManagerNotFound, name, uint32(err))
}

func (r *DecoderRegister) decoderManagerByTypeStatus(dcdType ocsd.TraceProtocol) (ocsd.DecoderManager, ocsd.Err) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if mngr, exists := r.typedManagers[dcdType]; exists {
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregTypeUnknown
}

// DecoderManagerByType retrieves a decoder manager by protocol and returns a Go error.
func (r *DecoderRegister) DecoderManagerByType(dcdType ocsd.TraceProtocol) (ocsd.DecoderManager, error) {
	mngr, err := r.decoderManagerByTypeStatus(dcdType)
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
	_, exists := r.decoderManagers[name]
	return exists
}

// IsRegisteredDecoderType checks whether a decoder manager is registered for a protocol.
func (r *DecoderRegister) IsRegisteredDecoderType(dcdType ocsd.TraceProtocol) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.typedManagers[dcdType]
	return exists
}

// Names returns a sorted snapshot of all registered decoder names.
func (r *DecoderRegister) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.namesLocked()
}

func (r *DecoderRegister) namesLocked() []string {
	names := make([]string, 0, len(r.decoderManagers))
	for name := range r.decoderManagers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
