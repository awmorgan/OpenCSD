package itm

import (
	"fmt"
	"opencsd/internal/ocsd"
)

// DecoderManager is the registry factory for ITM decoders
type DecoderManager struct {
}

// NewConfiguredPktProc creates an ITM packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ITM config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID
	proc := NewPktProc(cfg, nil)
	return proc, nil
}

// NewConfiguredPktDecode creates an ITM packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ITM config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID
	dec := NewPktDecode(cfg, nil)
	return dec, nil
}

// NewConfiguredPipeline creates and wires a typed ITM processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(dec)
	return proc, dec, nil
}

func typedConfig(config any) (*Config, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, ocsd.ErrInvalidParamType
	}
	return cfg, nil
}

func (m *DecoderManager) CreatePacketProcessor(instID int, config any) (ocsd.TrcDataProcessor, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, createErr := NewConfiguredPktProc(instID, cfg)
	if createErr != nil {
		return nil, nil, createErr
	}
	return proc, proc, nil
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (ocsd.TrcDataProcessor, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, dec, createErr := NewConfiguredPipeline(instID, cfg)
	if createErr != nil {
		return nil, nil, createErr
	}
	return proc, dec, nil
}

func (m *DecoderManager) Protocol() ocsd.TraceProtocol {
	return ocsd.ProtocolITM
}
