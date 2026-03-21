package ete

import (
	"opencsd/internal/etmv4"
	"opencsd/internal/interfaces"
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
	if decoder.SetProtocolConfig(cfg.ToETMv4Config()) != ocsd.OK {
		return nil, ocsd.ErrInvalidParamVal
	}
	return decoder, ocsd.OK
}

// NewConfiguredPipeline creates and wires a typed ETE processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*Processor, *PktDecode, ocsd.Err) {
	proc, err := NewConfiguredProcessor(cfg)
	if err != ocsd.OK {
		return nil, nil, err
	}
	decoder, err := NewConfiguredPktDecode(instID, cfg)
	if err != ocsd.OK {
		return nil, nil, err
	}
	proc.SetPktOut(decoder)
	return proc, decoder, ocsd.OK
}

func (m *DecoderManager) CreatePktProc(instID int, config any) interfaces.TrcTypedBase {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	proc, err := NewConfiguredProcessor(cfg)
	if err != ocsd.OK {
		return nil
	}
	return proc
}

func (m *DecoderManager) CreatePktDecode(instID int, config any) interfaces.TrcTypedBase {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	decoder, err := NewConfiguredPktDecode(instID, cfg)
	if err != ocsd.OK {
		return nil
	}
	return decoder
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, interfaces.TrcTypedBase, ocsd.Err) {
	cfg, ok := config.(*Config)
	if !ok {
		return nil, nil, ocsd.ErrInvalidParamVal
	}
	proc, decoder, err := NewConfiguredPipeline(instID, cfg)
	if err != ocsd.OK {
		return nil, nil, err
	}
	return proc, decoder, ocsd.OK
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolETE
}
