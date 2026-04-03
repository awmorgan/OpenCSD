package common

import "testing"

type fakeFlagApplier struct {
	applied uint32
}

func (f *fakeFlagApplier) ApplyFlags(flags uint32) error {
	f.applied |= flags
	return nil
}

func TestFlagApplierContract(t *testing.T) {
	var applier FlagApplier = &fakeFlagApplier{}
	if err := applier.ApplyFlags(0x11); err != nil {
		t.Fatalf("expected ApplyFlags to succeed, got %v", err)
	}
}
