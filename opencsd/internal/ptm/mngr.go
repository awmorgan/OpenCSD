package ptm

import (
	"fmt"
	"opencsd/internal/ocsd"
)

// NewConfiguredPktProc creates a PTM packet processor with a typed config.
func NewConfiguredPktProc(instID int, cfg *Config) (*PktProc, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: PTM config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID
	proc := NewPktProc(cfg, nil)
	return proc, nil
}

// NewConfiguredPktDecode creates a PTM packet decoder with a typed config.
func NewConfiguredPktDecode(instID int, cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: PTM config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID
	dec := NewPktDecode(cfg, nil)
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
