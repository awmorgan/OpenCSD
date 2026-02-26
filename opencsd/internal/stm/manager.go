package stm

// DecoderManager is the registry factory for STM decoders
type DecoderManager struct {
}

// NewDecoderManager creates a new STM decoder manager.
func NewDecoderManager() *DecoderManager {
	m := &DecoderManager{}
	return m
}

// Implement DecoderManagerBase overrides just by defining functions that return the appropriate components.
// Normally we'd register this in lib_dcd_register, but since the port uses Go idiomatic registries,
// we just provide the factory methods.

func (m *DecoderManager) CreatePktProc(instID int, config any) *PktProc {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	proc := NewPktProc(instID)
	proc.SetProtocolConfig(cfg)
	return proc
}

func (m *DecoderManager) CreatePktDecode(instID int, config any) *PktDecode {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	dec := NewPktDecode(instID)
	dec.SetProtocolConfig(cfg)
	return dec
}
