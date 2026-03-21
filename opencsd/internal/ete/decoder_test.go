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
	cfg := NewConfig()

	proc, err := NewConfiguredProcessor(cfg)
	if err != ocsd.OK {
		t.Fatalf("NewConfiguredProcessor err=%v", err)
	}
	if proc == nil {
		t.Fatalf("NewConfiguredProcessor returned nil")
	}

	dec, err := NewConfiguredPktDecode(1, cfg)
	if err != ocsd.OK {
		t.Fatalf("NewConfiguredPktDecode err=%v", err)
	}
	if dec == nil {
		t.Fatalf("NewConfiguredPktDecode returned nil")
	}
}

func TestDecoderManagerCreateDecoder(t *testing.T) {
	cfg := NewConfig()

	in, handle, err := NewDecoderManager().CreateDecoder(3, cfg)
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

func TestTypedPipelineConstructors(t *testing.T) {
	proc, dec, err := NewConfiguredPipeline(3, NewConfig())
	if err != ocsd.OK {
		t.Fatalf("NewConfiguredPipeline err=%v", err)
	}
	if proc == nil || dec == nil {
		t.Fatalf("NewConfiguredPipeline returned nil outputs")
	}

	if procOnly, err := NewConfiguredProcessor(nil); err != ocsd.ErrInvalidParamVal || procOnly != nil {
		t.Fatalf("expected nil-config processor constructor failure, got proc=%v err=%v", procOnly, err)
	}
	if decOnly, err := NewConfiguredPktDecode(0, nil); err != ocsd.ErrInvalidParamVal || decOnly != nil {
		t.Fatalf("expected nil-config decoder constructor failure, got dec=%v err=%v", decOnly, err)
	}
	if procOnly, decOnly, err := NewConfiguredPipeline(0, nil); err != ocsd.ErrInvalidParamVal || procOnly != nil || decOnly != nil {
		t.Fatalf("expected nil-config pipeline constructor failure, got proc=%v dec=%v err=%v", procOnly, decOnly, err)
	}
}

func TestDecoderManagerRejectsWrongConfigType(t *testing.T) {
	m := NewDecoderManager()

	if got := m.CreatePktProc(0, struct{}{}); got != nil {
		t.Fatalf("CreatePktProc expected nil for wrong config type")
	}

	in, handle, err := m.CreateDecoder(0, struct{}{})
	if err != ocsd.ErrInvalidParamVal {
		t.Fatalf("CreateDecoder err=%v want %v", err, ocsd.ErrInvalidParamVal)
	}
	if in != nil || handle != nil {
		t.Fatalf("CreateDecoder expected nil outputs for wrong config type")
	}
}
