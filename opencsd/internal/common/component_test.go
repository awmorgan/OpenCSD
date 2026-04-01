package common

import (
	"testing"
)

func TestComponentRuntimeViaDecoderBase(t *testing.T) {
	b := &DecoderBase{
		Name: "TestComp",
	}
	if b.Name != "TestComp" {
		t.Errorf("expected name TestComp, got %s", b.Name)
	}

	b.ConfigureSupportedOpModes(0x0F)
	err := b.SetComponentOpMode(0x01)
	if err != nil {
		t.Errorf("expected OK, got %v", err)
	}
	if b.ComponentOpMode() != 0x01 {
		t.Errorf("expected op mode 0x01, got 0x%x", b.ComponentOpMode())
	}

	err = b.SetComponentOpMode(0x10)
	if err != nil {
		t.Errorf("expected OK for unsupported-flag mask behaviour, got %v", err)
	}
	if b.ComponentOpMode() != 0x00 {
		t.Errorf("expected unsupported flags to be masked out, got 0x%x", b.ComponentOpMode())
	}
}
