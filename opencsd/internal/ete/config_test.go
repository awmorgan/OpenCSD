package ete

import (
	"testing"

	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

func TestNewConfigDefaults(t *testing.T) {
	cfg := NewConfig()
	if cfg == nil {
		t.Fatalf("NewConfig returned nil")
	}

	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{name: "RegDevArch", got: cfg.RegDevArch, want: defaultDevArch},
		{name: "RegIdr0", got: cfg.RegIdr0, want: defaultIDR0},
		{name: "RegIdr1", got: cfg.RegIdr1, want: defaultIDR1},
		{name: "RegIdr2", got: cfg.RegIdr2, want: defaultIDR2},
		{name: "RegConfigr", got: cfg.RegConfigr, want: defaultConfigR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got 0x%08x, want 0x%08x", tt.got, tt.want)
			}
		})
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
	cfg.RegConfigr = 0x0
	cfg.ArchVer = ocsd.ArchUnknown

	// maj=0x9 (bits 12-15), min=0x7 (bits 16-19)
	cfg.RegDevArch = (0x9 << devArchMajorShift) | (0x7 << devArchMinorShift)

	v4 := cfg.ToETMv4Config()
	if v4 == nil {
		t.Fatalf("ToETMv4Config returned nil")
	}
	assertETMv4OnlyRegsZero(t, v4)
	assertIDR1Version(t, v4.RegIdr1, 0x9, 0x7)

	if v4.RegConfigr&configWFIWFEBit == 0 {
		t.Fatalf("expected RegConfigr bit 17 to be forced high for WFI/WFE branch tracing")
	}
	if v4.ArchVer != ocsd.ArchAA64 {
		t.Fatalf("expected ArchVer to be forced to ArchAA64, got %v", v4.ArchVer)
	}
}

func TestToETMv4Config_DevArchZeroClearsMajMinOverride(t *testing.T) {
	cfg := NewConfig()
	cfg.RegIdr1 = 0x00000FF0
	cfg.RegDevArch = 0

	v4 := cfg.ToETMv4Config()
	if v4 == nil {
		t.Fatalf("ToETMv4Config returned nil")
	}
	assertIDR1Version(t, v4.RegIdr1, 0, 0)
}

func assertETMv4OnlyRegsZero(t *testing.T, cfg *etmv4.Config) {
	t.Helper()
	if cfg.RegIdr9 != 0 || cfg.RegIdr10 != 0 || cfg.RegIdr11 != 0 || cfg.RegIdr12 != 0 || cfg.RegIdr13 != 0 {
		t.Fatalf("expected ETMv4-only IDRs 9-13 to be zeroed")
	}
}

func assertIDR1Version(t *testing.T, idr1, wantMaj, wantMin uint32) {
	t.Helper()
	maj := (idr1 >> idr1MajorShift) & devArchVersionMask
	min := (idr1 >> idr1MinorShift) & devArchVersionMask
	if maj != wantMaj || min != wantMin {
		t.Fatalf("unexpected IDR1 version: maj=%d min=%d, want maj=%d min=%d", maj, min, wantMaj, wantMin)
	}
}
