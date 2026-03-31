package itm

import (
	"fmt"
	"opencsd/internal/ocsd"
)

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
