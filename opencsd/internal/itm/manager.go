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
	if err := proc.PktOutI.Replace(dec); ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	return proc, dec, ocsd.OK
}

func typedConfig(config any) (*Config, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, ocsd.ToError(ocsd.ErrInvalidParamType)
	}
	return cfg, nil
}

func (m *DecoderManager) CreateTypedPktProc(instID int, config any) (ocsd.TrcDataIn, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, createErr := NewConfiguredPktProc(instID, cfg)
	if ocsd.IsNotOK(createErr) {
		return nil, nil, ocsd.ToError(createErr)
	}
	return proc, proc, nil
}

func (m *DecoderManager) CreateTypedDecoder(instID int, config any) (ocsd.TrcDataIn, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, dec, createErr := NewConfiguredPipeline(instID, cfg)
	if ocsd.IsNotOK(createErr) {
		return nil, nil, ocsd.ToError(createErr)
	}
	return proc, dec, nil
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolITM
}
