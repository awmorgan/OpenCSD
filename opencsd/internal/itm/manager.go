package itm

import (
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

// NewPipeline creates and wires an ITM processor/decoder pair with optional dependencies.
// The config is required (instID is retained for backwards compatibility but not used).
// Dependencies (out, mem, instr) may be nil; when nil, the decoder operations that require
// them will fail at runtime (by design for packet-only or partial-decode modes).
func NewPipeline(instID int, cfg *Config, out ocsd.GenElemProcessor, mem common.TargetMemAccess, instr common.InstrDecode) (*PktProc, *PktDecode, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("%w: ITM config cannot be nil", ocsd.ErrInvalidParamVal)
	}
	_ = instID

	proc := NewPktProc(cfg)
	dec, err := NewPktDecode(cfg)
	if err != nil {
		return nil, nil, err
	}

	// Inject dependencies unconditionally (they may be nil).
	dec.SetTraceElemOut(out)
	dec.MemAccess = mem
	dec.InstrDecode = instr

	// Wire processor output to decoder input.
	proc.SetPktOut(dec)

	return proc, dec, nil
}
