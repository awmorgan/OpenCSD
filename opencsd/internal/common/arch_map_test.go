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

	arch, ok = m.GetArchProfile("Unknown-Core")
	if ok || arch != (ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}) {
		t.Errorf("Expected Unknown for invalid core")
	}
}
