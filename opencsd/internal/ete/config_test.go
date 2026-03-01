package ete

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestNewConfigDefaults(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatalf("NewConfig returned nil")
	}

	if cfg.RegDevArch != 0x47705A13 {
		t.Fatalf("unexpected RegDevArch default: 0x%08x", cfg.RegDevArch)
	}
	if cfg.RegIdr0 != 0x28000EA1 || cfg.RegIdr1 != 0x4100FFF3 || cfg.RegIdr2 != 0x00000488 {
		t.Fatalf("unexpected default IDR values: idr0=0x%08x idr1=0x%08x idr2=0x%08x", cfg.RegIdr0, cfg.RegIdr1, cfg.RegIdr2)
	}
	if cfg.RegConfigr != 0xC1 {
		t.Fatalf("unexpected RegConfigr default: 0x%08x", cfg.RegConfigr)
	}
	if cfg.ArchVer != ocsd.ArchAA64 {
		t.Fatalf("unexpected ArchVer default: %v", cfg.ArchVer)
	}
	if cfg.CoreProf != ocsd.ProfileCortexA {
		t.Fatalf("unexpected CoreProf default: %v", cfg.CoreProf)
	}
}

func TestToETMv4Config_MapsDevArchVersionAndZerosETMOnlyRegs(t *testing.T) {
	cfg := NewConfig()

	cfg.RegIdr1 = 0xFFFFFFFF
	cfg.RegIdr9 = 0x11111111
	cfg.RegIdr10 = 0x22222222
	cfg.RegIdr11 = 0x33333333
	cfg.RegIdr12 = 0x44444444
	cfg.RegIdr13 = 0x55555555

	// maj=0x9 (bits 12-15), min=0x7 (bits 16-19)
	cfg.RegDevArch = (0x9 << 12) | (0x7 << 16)

	v4 := cfg.ToETMv4Config()
	if v4 == nil {
		t.Fatalf("ToETMv4Config returned nil")
	}

	if v4.RegIdr9 != 0 || v4.RegIdr10 != 0 || v4.RegIdr11 != 0 || v4.RegIdr12 != 0 || v4.RegIdr13 != 0 {
		t.Fatalf("expected ETMv4-only IDRs 9-13 to be zeroed")
	}

	maj := (v4.RegIdr1 >> 8) & 0xF
	min := (v4.RegIdr1 >> 4) & 0xF
	if maj != 0x9 || min != 0x7 {
		t.Fatalf("unexpected maj/min from RegDevArch: maj=%d min=%d", maj, min)
	}
}
