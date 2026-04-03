package ptm

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// NewConfiguredPktProc creates a PTM packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: PTM config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID
	proc := NewPktProc(cfg)
	return proc, nil
}

// NewConfiguredPktDecode creates a PTM packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	_ = instID
	return NewPktDecode(cfg)
}

// NewConfiguredPktDecodeWithDeps creates a PTM decoder and injects dependencies.
func NewConfiguredPktDecodeWithDeps(instID int, cfg *Config, out ocsd.GenElemProcessor, mem common.TargetMemAccess, instr common.InstrDecode) (*PktDecode, error) {
	dec, err := NewConfiguredPktDecode(instID, cfg)
	if err != nil {
		return nil, err
	}
	dec.SetTraceElemOut(out)
	dec.MemAccess = mem
	dec.InstrDecode = instr
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
	proc.SetPktOut(dec)
	return proc, dec, nil
}

// NewConfiguredPipelineWithDeps creates and wires a PTM processor/decoder pair with dependencies.
func NewConfiguredPipelineWithDeps(instID int, cfg *Config, out ocsd.GenElemProcessor, mem common.TargetMemAccess, instr common.InstrDecode) (*PktProc, *PktDecode, error) {
	proc, err := NewConfiguredPktProc(instID, cfg)
	if err != nil {
		return nil, nil, err
	}
	dec, err := NewConfiguredPktDecodeWithDeps(instID, cfg, out, mem, instr)
	if err != nil {
		return nil, nil, err
	}
	proc.SetPktOut(dec)
	return proc, dec, nil
}
