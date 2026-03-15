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
	iterNames    []string
	iterPos      int
}

var defaultRegister = NewDecoderRegister()

// GetDecoderRegister returns the library's global singleton decoder registry.
func GetDecoderRegister() *DecoderRegister {
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

// GetFirstNamedDecoder starts iteration over registered decoder names.
func (r *DecoderRegister) GetFirstNamedDecoder() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.iterNames = r.iterNames[:0]
	for name := range r.decoderMngrs {
		r.iterNames = append(r.iterNames, name)
	}
	sort.Strings(r.iterNames)
	r.iterPos = 0
	return r.getNextNamedDecoderLocked()
}

// GetNextNamedDecoder returns the next decoder name in iteration.
func (r *DecoderRegister) GetNextNamedDecoder() (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.getNextNamedDecoderLocked()
}

func (r *DecoderRegister) getNextNamedDecoderLocked() (string, bool) {
	if r.iterPos >= len(r.iterNames) {
		return "", false
	}
	name := r.iterNames[r.iterPos]
	r.iterPos++
	return name, true
}
