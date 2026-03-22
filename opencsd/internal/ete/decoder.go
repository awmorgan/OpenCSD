package ete

import (
	"opencsd/internal/common"
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

type PktDecode = etmv4.PktDecode

func NewPktDecode(cfg *Config, logger ocsd.Logger) *PktDecode {
	if cfg == nil {
		return etmv4.NewPktDecode(nil, logger)
	}
	return etmv4.NewPktDecode(cfg.ToETMv4Config(), logger)
}

type DecoderManager struct{}

// NewConfiguredProcessor creates an ETE packet processor with a typed config.
func NewConfiguredProcessor(cfg *Config) (*Processor, error) {
	if cfg == nil {
		return nil, common.Errorf(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "ETE config cannot be nil")
	}
	return NewProcessor(cfg), nil
}

// NewConfiguredPktDecode creates an ETE packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, common.Errorf(ocsd.ErrSevError, ocsd.ErrInvalidParamVal, "ETE config cannot be nil")
	}
	_ = instID
	decoder := NewPktDecode(cfg, nil)
	return decoder, nil
}

// NewConfiguredPipeline creates and wires a typed ETE processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*Processor, *PktDecode, error) {
	proc, err := NewConfiguredProcessor(cfg)
	if err != nil {
		return nil, nil, err
	}
	decoder, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(decoder)
	return proc, decoder, nil
}

func typedConfig(config any) (*Config, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, ocsd.ToError(ocsd.ErrInvalidParamVal)
	}
	return cfg, nil
}

func (m *DecoderManager) CreatePacketProcessor(instID int, config any) (ocsd.TrcDataProcessor, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, createErr := NewConfiguredProcessor(cfg)
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
	proc, decoder, createErr := NewConfiguredPipeline(instID, cfg)
	if createErr != nil {
		return nil, nil, createErr
	}
	return proc, decoder, nil
}

func (m *DecoderManager) Protocol() ocsd.TraceProtocol {
	return ocsd.ProtocolETE
}
