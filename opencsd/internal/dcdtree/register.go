package dcdtree

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
	"sort"
	"sync"
)

// DecoderRegister manages decoder protocol factories for the library.
type DecoderRegister struct {
	mu           sync.RWMutex
	decoderMngrs map[string]interfaces.DecoderMngr
	typedMngrs   map[ocsd.TraceProtocol]interfaces.DecoderMngr
	nextCustomID ocsd.TraceProtocol
	lastTyped    interfaces.DecoderMngr
}

var defaultRegister = NewBuiltinDecoderRegister()

// DefaultDecoderRegister returns the package-level registry populated with built-in decoders.
func DefaultDecoderRegister() *DecoderRegister {
	return defaultRegister
}

// GetDecoderRegister returns the library's global singleton decoder registry.
// Prefer passing a registry explicitly where practical.
func GetDecoderRegister() *DecoderRegister {
	return DefaultDecoderRegister()
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

// GetDecoderMngrByName retrieves a decoder factory by its registered name string.
func (r *DecoderRegister) GetDecoderMngrByName(name string) (interfaces.DecoderMngr, ocsd.Err) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if mngr, exists := r.decoderMngrs[name]; exists {
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregNameUnknown
}

// GetDecoderMngrByType retrieves a decoder factory by its protocol enum value.
func (r *DecoderRegister) GetDecoderMngrByType(dcdType ocsd.TraceProtocol) (interfaces.DecoderMngr, ocsd.Err) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastTyped != nil && r.lastTyped.ProtocolType() == dcdType {
		return r.lastTyped, ocsd.OK
	}
	if mngr, exists := r.typedMngrs[dcdType]; exists {
		r.lastTyped = mngr
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregTypeUnknown
}

// GetNextCustomProtocolID allocates the next custom protocol ID.
func (r *DecoderRegister) GetNextCustomProtocolID() ocsd.TraceProtocol {
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
