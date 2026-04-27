package stm

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: STM config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	return nil
}

// NewConfiguredPktProc creates an STM packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	_ = instID
	return NewPktProc(cfg), nil
}

// NewConfiguredPktDecode creates an STM packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	_ = instID
	return NewPktDecode(cfg)
}

// NewConfiguredPktDecodeWithDeps creates an STM decoder and injects dependencies.
// source is the pull-based PacketReader to use; pass nil to use the push-based Write path.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode, source ocsd.PacketReader[Packet]) (*PktDecode, error) {
	dec, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, err
	}
	dec.MemAccess = mem
	dec.InstrDecode = instr
	dec.Source = source
	return dec, nil
}

// NewConfiguredPipeline creates and wires a typed STM processor/decoder pair.
func NewConfiguredPipeline(instID int, cfg *Config) (*PktProc, *PktDecode, error) {
	return NewConfiguredPipelineWithDeps(instID, cfg, nil, nil)
}

// NewConfiguredPipelineWithDeps creates and wires an STM processor/decoder pair with dependencies.
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, mem common.TargetMemAccess, instr common.InstrDecode) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}

	dec, err := NewConfiguredPktDecodeWithDeps(instID, cfg, mem, instr, proc)
	if err != nil {
		return nil, nil, err
	}
	return proc, dec, nil
}
