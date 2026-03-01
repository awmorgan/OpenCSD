package ete

import (
	"testing"

	"opencsd/internal/interfaces"
	"opencsd/internal/ocsd"
)

func TestDecoderManagerProtocolType(t *testing.T) {
	m := NewDecoderManager()
	if got := m.ProtocolType(); got != ocsd.ProtocolETE {
		t.Fatalf("ProtocolType=%v want %v", got, ocsd.ProtocolETE)
	}
}

func TestDecoderManagerCreatePktProcAndDecode(t *testing.T) {
	m := NewDecoderManager()
	cfg := NewConfig()

	procAny := m.CreatePktProc(1, cfg)
	if procAny == nil {
		t.Fatalf("CreatePktProc returned nil")
	}
	if _, ok := procAny.(*Processor); !ok {
		t.Fatalf("CreatePktProc returned unexpected type %T", procAny)
	}

	decAny := m.CreatePktDecode(1, cfg)
	if decAny == nil {
		t.Fatalf("CreatePktDecode returned nil")
	}
	if _, ok := decAny.(*PktDecode); !ok {
		t.Fatalf("CreatePktDecode returned unexpected type %T", decAny)
	}
}

func TestDecoderManagerCreateDecoder(t *testing.T) {
	m := NewDecoderManager()
	cfg := NewConfig()

	in, handle, err := m.CreateDecoder(3, cfg)
	if err != ocsd.OK {
		t.Fatalf("CreateDecoder err=%v", err)
	}
	if in == nil || handle == nil {
		t.Fatalf("CreateDecoder returned nil outputs")
	}
	if _, ok := in.(interfaces.TrcDataIn); !ok {
		t.Fatalf("CreateDecoder input does not implement TrcDataIn")
	}
}

func TestDecoderManagerRejectsWrongConfigType(t *testing.T) {
	m := NewDecoderManager()

	if got := m.CreatePktProc(0, struct{}{}); got != nil {
		t.Fatalf("CreatePktProc expected nil for wrong config type")
	}
	if got := m.CreatePktDecode(0, struct{}{}); got != nil {
		t.Fatalf("CreatePktDecode expected nil for wrong config type")
	}

	in, handle, err := m.CreateDecoder(0, struct{}{})
	if err != ocsd.ErrInvalidParamVal {
		t.Fatalf("CreateDecoder err=%v want %v", err, ocsd.ErrInvalidParamVal)
	}
	if in != nil || handle != nil {
		t.Fatalf("CreateDecoder expected nil outputs for wrong config type")
	}
}
