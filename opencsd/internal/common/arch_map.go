package common

import "opencsd/internal/ocsd"

// CoreArchProfileMap maps core names to architecture profiles.
type CoreArchProfileMap struct {
	coreMap map[string]ocsd.ArchProfile
}

// NewCoreArchProfileMap creates a new map.
func NewCoreArchProfileMap() *CoreArchProfileMap {
	m := &CoreArchProfileMap{
		coreMap: make(map[string]ocsd.ArchProfile),
	}
	m.initMap()
	return m
}

func (m *CoreArchProfileMap) initMap() {
	m.coreMap["Cortex-A53"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A57"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A72"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A15"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A7"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A9"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-R4"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["Cortex-R5"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["Cortex-R7"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["Cortex-M3"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-M4"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-A35"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A32"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	// Custom fallback architectures
	m.coreMap["ARMv7-A"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["ARMv7-R"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["ARMv7-M"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}
	m.coreMap["ARMv8-A"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["ARMv8-R"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexR}
	m.coreMap["ARMv8-M"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM}
	m.coreMap["ARMv9-A"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA} // Treat V9 mostly like V8 for decode currently
}

// GetArchProfile returns the architecture profile for a given core name.
func (m *CoreArchProfileMap) GetArchProfile(coreName string) (ocsd.ArchProfile, bool) {
	if val, ok := m.coreMap[coreName]; ok {
		return val, true
	}
	return ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}, false
}
