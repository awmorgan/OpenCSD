package ete

import (
	"errors"
	"testing"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

func TestDecoderManagerProtocolType(t *testing.T) {
	m := &DecoderManager{}
	if got := m.Protocol(); got != ocsd.ProtocolETE {
		t.Fatalf("Protocol=%v want %v", got, ocsd.ProtocolETE)
	}
}

func TestDecoderManagerCreatePktProcAndDecode(t *testing.T) {
	cfg := NewConfig()

	proc, err := NewConfiguredProcessor(cfg)
	if err != nil {
		t.Fatalf("NewConfiguredProcessor err=%v", err)
	}
	if proc == nil {
		t.Fatalf("NewConfiguredProcessor returned nil")
	}

	dec, err := NewConfiguredPktDecode(1, cfg)
	if err != nil {
		t.Fatalf("NewConfiguredPktDecode err=%v", err)
	}
	if dec == nil {
		t.Fatalf("NewConfiguredPktDecode returned nil")
	}
}

func TestDecoderManagerCreateDecoder(t *testing.T) {
	cfg := NewConfig()

	in, handle, err := (&DecoderManager{}).CreateDecoder(3, cfg)
	if err != nil {
		t.Fatalf("CreateDecoder err=%v", err)
	}
	if in == nil || handle == nil {
		t.Fatalf("CreateDecoder returned nil outputs")
	}
	if _, ok := in.(ocsd.TrcDataIn); !ok {
		t.Fatalf("CreateDecoder input does not implement TrcDataIn")
	}
}

func TestTypedPipelineConstructors(t *testing.T) {
	proc, dec, err := NewConfiguredPipeline(3, NewConfig())
	if err != nil {
		t.Fatalf("NewConfiguredPipeline err=%v", err)
	}
	if proc == nil || dec == nil {
		t.Fatalf("NewConfiguredPipeline returned nil outputs")
	}

	if procOnly, err := NewConfiguredProcessor(nil); procOnly != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config processor constructor failure, got proc=%v err=%v", procOnly, err)
	}
	if decOnly, err := NewConfiguredPktDecode(0, nil); decOnly != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config decoder constructor failure, got dec=%v err=%v", decOnly, err)
	}
	if procOnly, decOnly, err := NewConfiguredPipeline(0, nil); procOnly != nil || decOnly != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config pipeline constructor failure, got proc=%v dec=%v err=%v", procOnly, decOnly, err)
	}
}

func TestDecoderManagerRejectsWrongConfigType(t *testing.T) {
	m := &DecoderManager{}

	in, handle, err := m.CreatePacketProcessor(0, struct{}{})
	if got := ocsd.AsErr(err); got != ocsd.ErrInvalidParamVal {
		t.Fatalf("CreatePacketProcessor err=%v want %v", err, ocsd.ErrInvalidParamVal)
	}
	if in != nil || handle != nil {
		t.Fatalf("CreatePacketProcessor expected nil outputs for wrong config type")
	}

	in, handle, err = m.CreateDecoder(0, struct{}{})
	if got := ocsd.AsErr(err); got != ocsd.ErrInvalidParamVal {
		t.Fatalf("CreateDecoder err=%v want %v", err, ocsd.ErrInvalidParamVal)
	}
	if in != nil || handle != nil {
		t.Fatalf("CreateDecoder expected nil outputs for wrong config type")
	}
}

func isErrorCode(err error, code ocsd.Err) bool {
	if err == nil {
		return false
	}
	var libErr *common.Error
	if !errors.As(err, &libErr) {
		return false
	}
	return libErr.Code == code
}
