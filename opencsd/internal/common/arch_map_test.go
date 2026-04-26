package common

import (
	"testing"

	"opencsd/internal/ocsd"
)

func TestArchProfileMap(t *testing.T) {
	tests := []struct {
		name string
		core string
		want ocsd.ArchProfile
		ok   bool
	}{
		{
			name: "known Cortex core",
			core: "Cortex-A53",
			want: ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA},
			ok:   true,
		},
		{
			name: "ARMv7 R profile",
			core: "ARMv7-R",
			want: ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR},
			ok:   true,
		},
		{
			name: "ARMv8.3 A profile",
			core: "ARMv8.3-A",
			want: ocsd.ArchProfile{Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA},
			ok:   true,
		},
		{
			name: "ARMv8.4 A profile",
			core: "ARMv8.4-A",
			want: ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexA},
			ok:   true,
		},
		{
			name: "ARMv9 A profile",
			core: "ARMv9-A",
			want: ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexA},
			ok:   true,
		},
		{
			name: "lowercase AA64 R profile",
			core: "ARM-aa64-R",
			want: ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexR},
			ok:   true,
		},
		{
			name: "uppercase AA64 M profile",
			core: "ARM-AA64-M",
			want: ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexM},
			ok:   true,
		},
		{
			name: "unsupported ARMv6",
			core: "ARMv6-M",
			want: ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown},
		},
		{
			name: "unknown core",
			core: "Unknown-Core",
			want: ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown},
		},
	}

	m := NewCoreArchProfileMap()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := m.ArchProfile(tc.core)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("ArchProfile(%q) = (%+v, %t), want (%+v, %t)", tc.core, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNewCoreArchProfileMapDoesNotShareDefaultMap(t *testing.T) {
	m1 := NewCoreArchProfileMap()
	m2 := NewCoreArchProfileMap()

	m1.coreMap["Unit-Test-Core"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}

	if _, ok := m2.coreMap["Unit-Test-Core"]; ok {
		t.Fatal("expected second map to be unchanged when first map is mutated")
	}
}
