package ptm

import (
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// DecoderManager is the registry factory for PTM decoders
type DecoderManager struct {
}

// NewConfiguredPktProc creates a PTM packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, error) {
	if cfg == nil {
		return nil, common.Errorf(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "PTM config cannot be nil")
	}
	proc := NewPktProc(instID)
	if err := proc.SetProtocolConfig(cfg); err != ocsd.OK {
		return nil, ocsd.ToError(err)
	}
	return proc, nil
}

// NewConfiguredPktDecode creates a PTM packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, common.Errorf(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "PTM config cannot be nil")
	}
	dec := NewPktDecode(instID)
	if err := dec.SetProtocolConfig(cfg); err != ocsd.OK {
		return nil, ocsd.ToError(err)
	}
	return dec, nil
}

// NewConfiguredPipeline creates and wires a typed PTM processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := proc.PktOutI.Attach(dec); err != ocsd.OK {
		return nil, nil, ocsd.ToError(err)
	}
	return proc, dec, nil
}

func typedConfig(config any) (*Config, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, ocsd.ToError(ocsd.ErrInvalidParamType)
	}
	return cfg, nil
}

func (m *DecoderManager) CreatePacketProcessor(instID int, config any) (ocsd.TrcDataIn, any, error) {
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

func (m *DecoderManager) CreateDecoder(instID int, config any) (ocsd.TrcDataIn, any, error) {
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
	return ocsd.ProtocolPTM
}
