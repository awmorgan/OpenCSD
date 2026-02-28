package itm

import (
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

// DecoderManager is the registry factory for ITM decoders
type DecoderManager struct {
}

// NewDecoderManager creates a new ITM decoder manager.
func NewDecoderManager() *DecoderManager {
	m := &DecoderManager{}
	return m
}

func (m *DecoderManager) CreatePktProc(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	proc := NewPktProc(instID)
	proc.SetProtocolConfig(cfg)
	return proc
}

func (m *DecoderManager) CreatePktDecode(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	dec := NewPktDecode(instID)
	dec.SetProtocolConfig(cfg)
	return dec
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	procAny := m.CreatePktProc(instID, config)
	if procAny == nil {
		return nil, nil, ocsd.ErrInvalidParamType
	}
	decAny := m.CreatePktDecode(instID, config)
	if decAny == nil {
		return nil, nil, ocsd.ErrInvalidParamType
	}
	proc := procAny.(*PktProc)
	dec := decAny.(*PktDecode)
	proc.PktOutI.ReplaceFirst(dec)
	return proc, dec, ocsd.OK
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolITM
}
