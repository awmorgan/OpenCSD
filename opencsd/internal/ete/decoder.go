package ete

import (
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

type PktDecode = etmv4.PktDecode

func NewPktDecode(instID int) *PktDecode {
	return etmv4.NewPktDecode(instID)
}

type DecoderManager struct{}

func NewDecoderManager() *DecoderManager {
	return &DecoderManager{}
}

// NewConfiguredProcessor creates an ETE packet processor with a typed config.
func NewConfiguredProcessor(cfg *Config) (*Processor, ocsd.Err) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	return NewProcessor(cfg), ocsd.OK
}

// NewConfiguredPktDecode creates an ETE packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, ocsd.Err) {
	if cfg == nil {
		return nil, ocsd.ErrInvalidParamVal
	}
	decoder := NewPktDecode(instID)
	if err := decoder.SetProtocolConfig(cfg.ToETMv4Config()); ocsd.IsNotOK(err) {
		return nil, ocsd.ErrInvalidParamVal
	}
	return decoder, ocsd.OK
}

// NewConfiguredPipeline creates and wires a typed ETE processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*Processor, *PktDecode, ocsd.Err) {
	proc, err := NewConfiguredProcessor(cfg)
	if ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	decoder, err := NewConfiguredPktDecode(instID, cfg)
	if ocsd.IsNotOK(err) {
		return nil, nil, err
	}
	proc.SetPktOut(decoder)
	return proc, decoder, ocsd.OK
}

func typedConfig(config any) (*Config, error) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, ocsd.ToError(ocsd.ErrInvalidParamVal)
	}
	return cfg, nil
}

func (m *DecoderManager) CreatePacketProcessor(instID int, config any) (ocsd.TrcDataIn, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, createErr := NewConfiguredProcessor(cfg)
	if ocsd.IsNotOK(createErr) {
		return nil, nil, ocsd.ToError(createErr)
	}
	return proc, proc, nil
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (ocsd.TrcDataIn, any, error) {
	cfg, err := typedConfig(config)
	if err != nil {
		return nil, nil, err
	}
	proc, decoder, createErr := NewConfiguredPipeline(instID, cfg)
	if ocsd.IsNotOK(createErr) {
		return nil, nil, ocsd.ToError(createErr)
	}
	return proc, decoder, nil
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolETE
}
