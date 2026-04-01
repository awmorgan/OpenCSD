package ete

import (
	"fmt"
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

type PktDecode = etmv4.PktDecode

func NewPktDecode(cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	return etmv4.NewPktDecode(cfg.ToETMv4Config())
}

// NewConfiguredProcessor creates an ETE packet processor with a typed config.
func NewConfiguredProcessor(cfg *Config) (*Processor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	return NewProcessor(cfg), nil
}

// NewConfiguredPktDecode creates an ETE packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	_ = instID
	return NewPktDecode(cfg)
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
