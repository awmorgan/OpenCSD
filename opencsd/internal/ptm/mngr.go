package ptm

// DecoderManager is the registry factory for PTM decoders
type DecoderManager struct {
}

// NewDecoderManager creates a new PTM decoder manager.
func NewDecoderManager() *DecoderManager {
	m := &DecoderManager{}
	return m
}

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
