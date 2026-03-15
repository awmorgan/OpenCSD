package common

import (
	"opencsd/internal/ocsd"
	"testing"
)

func TestArchProfileMap(t *testing.T) {
	m := NewCoreArchProfileMap()
	arch, ok := m.GetArchProfile("Cortex-A53")
	if !ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}) {
		t.Errorf("Expected ArchV8 for Cortex-A53")
	}

	arch, ok = m.GetArchProfile("ARMv7-R")
	if !ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}) {
		t.Errorf("Expected ArchV7R for ARMv7-R")
	}

	arch, ok = m.GetArchProfile("ARMv8.3-A")
	if !ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA}) {
		t.Errorf("Expected ArchV8r3/A for ARMv8.3-A")
	}

	arch, ok = m.GetArchProfile("ARMv8.4-A")
	if !ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexA}) {
		t.Errorf("Expected ArchAA64/A for ARMv8.4-A")
	}

	arch, ok = m.GetArchProfile("ARMv9-A")
	if !ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexA}) {
		t.Errorf("Expected ArchAA64/A for ARMv9-A")
	}

	arch, ok = m.GetArchProfile("ARM-aa64-R")
	if !ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexR}) {
		t.Errorf("Expected ArchAA64/R for ARM-aa64-R")
	}

	arch, ok = m.GetArchProfile("ARM-AA64-M")
	if !ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexM}) {
		t.Errorf("Expected ArchAA64/M for ARM-AA64-M")
	}

	arch, ok = m.GetArchProfile("ARMv6-M")
	if ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}) {
		t.Errorf("Expected Unknown for ARMv6-M")
	}

	arch, ok = m.GetArchProfile("Unknown-Core")
	if ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}) {
		t.Errorf("Expected Unknown for invalid core")
	}
}
