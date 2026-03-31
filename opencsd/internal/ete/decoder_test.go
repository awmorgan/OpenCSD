package ete

import (
	"errors"
	"testing"

	"opencsd/internal/ocsd"
)

func TestCreatePktProcAndDecode(t *testing.T) {
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

func isErrorCode(err error, code error) bool {
	return errors.Is(err, code)
}
