package itm

import (
	"opencsd/internal/ocsd"
)

// DecoderManager is the registry factory for ITM decoders
type DecoderManager struct {
}

// NewDecoderManager creates a new ITM decoder manager.
func NewDecoderManager() *DecoderManager {
	return &DecoderManager{}
}

// NewConfiguredPktProc creates an ITM packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, ocsd.Err) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	proc := NewPktProc(instID)
	if err := proc.SetProtocolConfig(cfg); ocsd.IsNotOK(err) {
		return nil, err
	}
	return proc, ocsd.OK
}

// NewConfiguredPktDecode creates an ITM packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, ocsd.Err) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	dec := NewPktDecode(instID)
	if err := dec.SetProtocolConfig(cfg); ocsd.IsNotOK(err) {
		return nil, err
	}
	return dec, ocsd.OK
}

// NewConfiguredPipeline creates and wires a typed ITM processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*PktProc, *PktDecode, ocsd.Err) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecode(instID, cfg)
	if ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	if err := proc.PktOutI.ReplaceFirst(dec); ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	return proc, dec, ocsd.OK
}

func (m *DecoderManager) CreateTypedPktProc(instID int, config any) (ocsd.TrcDataIn, any, ocsd.Err) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, nil, ocsd.ErrInvalidParamType
	}
	proc, err := NewConfiguredPktProc(instID, cfg)
	if ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	return proc, proc, ocsd.OK
}

func (m *DecoderManager) CreateTypedDecoder(instID int, config any) (ocsd.TrcDataIn, any, ocsd.Err) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, nil, ocsd.ErrInvalidParamType
	}
	proc, dec, err := NewConfiguredPipeline(instID, cfg)
	if ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	return proc, dec, ocsd.OK
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolITM
}
