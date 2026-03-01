package ete

import (
	"opencsd/internal/etmv4"
	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

type PktDecode = etmv4.PktDecode

func NewPktDecode(instID int) *PktDecode {
	return etmv4.NewPktDecode(instID)
}

type DecoderManager struct{}

func NewDecoderManager() *DecoderManager {
	return &DecoderManager{}
}

func (m *DecoderManager) CreatePktProc(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}
	return NewProcessor(cfg)
}

func (m *DecoderManager) CreatePktDecode(instID int, config any) any {
	cfg, ok := config.(*Config)
	if !ok {
		return nil
	}

	decoder := NewPktDecode(instID)
	if decoder.SetProtocolConfig(cfg.ToETMv4Config()) != ocsd.OK {
		return nil
	}
	return decoder
}

func (m *DecoderManager) CreateDecoder(instID int, config any) (interfaces.TrcDataIn, any, ocsd.Err) {
	procAny := m.CreatePktProc(instID, config)
	if procAny == nil {
		return nil, nil, ocsd.ErrInvalidParamVal
	}
	decAny := m.CreatePktDecode(instID, config)
	if decAny == nil {
		return nil, nil, ocsd.ErrInvalidParamVal
	}

	proc := procAny.(*Processor)
	decoder := decAny.(*PktDecode)
	proc.SetPktOut(decoder)
	return proc, decoder, ocsd.OK
}

func (m *DecoderManager) ProtocolType() ocsd.TraceProtocol {
	return ocsd.ProtocolETE
}
