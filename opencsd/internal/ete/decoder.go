package ete

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

func NewPktDecode(cfg *Config) (*etmv4.PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	return etmv4.NewPktDecode(cfg.ToETMv4Config())
}

// NewConfiguredProcessor creates an ETE packet processor with a typed config.
func NewConfiguredProcessor(cfg *Config) (*etmv4.Processor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETE config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	return NewProcessor(cfg), nil
}

// NewConfiguredPktDecode creates an ETE packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*etmv4.PktDecode, error) {
	_ = instID
	return NewPktDecode(cfg)
}

// NewConfiguredPktDecodeWithDeps creates an ETE decoder and injects dependencies.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, out ocsd.GenElemProcessor, mem common.TargetMemAccess, instr common.InstrDecode) (*etmv4.PktDecode, error) {
	decoder, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, err
	}
	decoder.SetTraceElemOut(out)
	decoder.SetMemAccess(mem)
	decoder.SetInstrDecode(instr)
	return decoder, nil
}

// NewConfiguredPipeline creates and wires a typed ETE processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*etmv4.Processor, *etmv4.PktDecode, error) {
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

// NewConfiguredPipelineWithDeps creates and wires an ETE processor/decoder pair with dependencies.
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, out ocsd.GenElemProcessor, mem common.TargetMemAccess, instr common.InstrDecode) (*etmv4.Processor, *etmv4.PktDecode, error) {
	proc, err := NewConfiguredProcessor(cfg)
	if err != nil {
		return nil, nil, err
	}
	decoder, err := NewConfiguredPktDecodeWithDeps(instID, cfg, out, mem, instr)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(decoder)
	return proc, decoder, nil
}
