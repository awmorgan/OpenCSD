package stm

import (
	"opencsd/internal/ocsd"
)

// DecoderManager is the registry factory for STM decoders
type DecoderManager struct {
}

// NewDecoderManager creates a new STM decoder manager.
func NewDecoderManager() *DecoderManager {
	return &DecoderManager{}
}

// NewConfiguredPktProc creates an STM packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, ocsd.Err) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	proc := NewPktProc(instID)
	if err := proc.SetProtocolConfig(cfg); err != ocsd.OK {
		return nil, err
	}
	return proc, ocsd.OK
}

// NewConfiguredPktDecode creates an STM packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, ocsd.Err) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	dec := NewPktDecode(instID)
	if err := dec.SetProtocolConfig(cfg); err != ocsd.OK {
		return nil, err
	}
	return dec, ocsd.OK
}

// NewConfiguredPipeline creates and wires a typed STM processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*PktProc, *PktDecode, ocsd.Err) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != ocsd.OK {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecode(instID, cfg)
	if err != ocsd.OK {
		return nil, nil, err
	}
	if err := proc.PktOutI.Replace(dec); err != ocsd.OK {
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

// Implement DecoderManagerBase overrides just by defining functions that return the appropriate components.
// Normally we'd register this in lib_dcd_register, but since the port uses Go idiomatic registries,
// we just provide the factory methods.

func (m *DecoderManager) CreatePacketProcessor(instID int, config any) (ocsd.TrcDataIn, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, createErr := NewConfiguredPktProc(instID, cfg)
	if createErr != ocsd.OK {
		return nil, nil, ocsd.ToError(createErr)
	}
	return proc, proc, nil
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (ocsd.TrcDataIn, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, dec, createErr := NewConfiguredPipeline(instID, cfg)
	if createErr != ocsd.OK {
		return nil, nil, ocsd.ToError(createErr)
	}
	return proc, dec, nil
}

func (m *DecoderManager) Protocol() ocsd.TraceProtocol {
	return ocsd.ProtocolSTM
}
