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
	// Cortex-A Series
	m.coreMap["Cortex-A77"] = ocsd.ArchProfile{Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA} // Assuming ArchV8r3 exists
	m.coreMap["Cortex-A76"] = ocsd.ArchProfile{Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A75"] = ocsd.ArchProfile{Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A73"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A72"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A65"] = ocsd.ArchProfile{Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A57"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A55"] = ocsd.ArchProfile{Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A53"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A35"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A32"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A17"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A15"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A12"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A9"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A8"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A7"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["Cortex-A5"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}

	// Cortex-R Series
	m.coreMap["Cortex-R52"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexR}
	m.coreMap["Cortex-R8"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["Cortex-R7"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["Cortex-R5"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["Cortex-R4"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}

	// Cortex-M Series
	m.coreMap["Cortex-M55"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-M33"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-M23"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-M4"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-M3"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-M0+"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}
	m.coreMap["Cortex-M0"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}

	// Custom fallback architectures
	m.coreMap["ARMv7-A"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA}
	m.coreMap["ARMv7-R"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR}
	m.coreMap["ARMv7-M"] = ocsd.ArchProfile{Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM}
	m.coreMap["ARMv8-A"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
	m.coreMap["ARMv8.x-A"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA} // Added from header
	m.coreMap["ARMv8-R"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexR}
	m.coreMap["ARMv8-M"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM}
	m.coreMap["ARM-AA64"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA} // Added from header
	m.coreMap["ARM-aa64"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA} // Added from header
	m.coreMap["ARMv9-A"] = ocsd.ArchProfile{Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA}
}

// GetArchProfile returns the architecture profile for a given core name.
func (m *CoreArchProfileMap) GetArchProfile(coreName string) (ocsd.ArchProfile, bool) {
	if val, ok := m.coreMap[coreName]; ok {
		return val, true
	}
	return ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}, false
}
