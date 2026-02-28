package dcdtree

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

// DecoderRegister manages decoder protocol factories for the library.
type DecoderRegister struct {
	decoderMngrs map[string]interfaces.DecoderMngr
	typedMngrs   map[ocsd.TraceProtocol]interfaces.DecoderMngr
	nextCustomID ocsd.TraceProtocol
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
	if _, exists := r.decoderMngrs[name]; exists {
		return ocsd.ErrDcdregNameRepeat
	}
	r.decoderMngrs[name] = mngr
	if mngr.ProtocolType() != ocsd.ProtocolUnknown {
		r.typedMngrs[mngr.ProtocolType()] = mngr
	}
	return ocsd.OK
}

// GetDecoderMngrByName retrieves a decoder factory by its registered name string.
func (r *DecoderRegister) GetDecoderMngrByName(name string) (interfaces.DecoderMngr, ocsd.Err) {
	if mngr, exists := r.decoderMngrs[name]; exists {
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregNameUnknown
}

// GetDecoderMngrByType retrieves a decoder factory by its protocol enum value.
func (r *DecoderRegister) GetDecoderMngrByType(dcdType ocsd.TraceProtocol) (interfaces.DecoderMngr, ocsd.Err) {
	if mngr, exists := r.typedMngrs[dcdType]; exists {
		return mngr, ocsd.OK
	}
	return nil, ocsd.ErrDcdregTypeUnknown
}
