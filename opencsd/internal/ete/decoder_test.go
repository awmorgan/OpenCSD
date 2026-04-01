package ete

import (
	"errors"
	"testing"

	"opencsd/internal/ocsd"
)

func TestCreatePktProcAndDecode(t *testing.T) {
	cfg := NewConfig()

	proc := NewProcessor(cfg)
	if proc == nil {
		t.Fatalf("NewProcessor returned nil")
	}

	dec, err := NewPktDecode(cfg)
	if err != nil {
		t.Fatalf("NewPktDecode err=%v", err)
	}
	if dec == nil {
		t.Fatalf("NewPktDecode returned nil")
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

	if procOnly := NewProcessor(nil); procOnly == nil {
		t.Fatalf("expected default-config processor for nil config, got nil")
	}
	if decOnly, err := NewPktDecode(nil); decOnly != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config decoder constructor failure, got dec=%v err=%v", decOnly, err)
	}
	if procOnly, decOnly, err := NewConfiguredPipeline(0, nil); procOnly != nil || decOnly != nil || !isErrorCode(err, ocsd.ErrInvalidParamVal) {
		t.Fatalf("expected nil-config pipeline constructor failure, got proc=%v dec=%v err=%v", procOnly, decOnly, err)
	}
}

func isErrorCode(err error, code error) bool {
	return errors.Is(err, code)
}
