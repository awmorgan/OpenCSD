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
}

// GetArchProfile returns the architecture profile for a given core name.
func (m *CoreArchProfileMap) GetArchProfile(coreName string) (ocsd.ArchProfile, bool) {
	if val, ok := m.coreMap[coreName]; ok {
		return val, true
	}

	if val, ok := getPatternMatchCoreName(coreName); ok {
		return val, true
	}

	return ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}, false
}

func getPatternMatchCoreName(coreName string) (ocsd.ArchProfile, bool) {
	ap := ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}

	if len(coreName) >= 5 && coreName[:4] == "ARMv" {
		if len(coreName) <= 4 {
			return ap, false
		}

		majver := int(coreName[4] - '0')
		minver := 0
		dotoffset := 0

		dotPos := -1
		for i := 0; i < len(coreName); i++ {
			if coreName[i] == '.' {
				dotPos = i
				break
			}
		}

		if dotPos == 5 {
			if len(coreName) <= 6 {
				return ap, false
			}
			minver = int(coreName[6] - '0')
			dotoffset = 2
		} else if dotPos != -1 {
			return ap, false
		}

		if majver == 7 {
			ap.Arch = ocsd.ArchV7
		} else if majver >= 8 {
			ap.Arch = ocsd.ArchAA64
			if majver == 8 {
				if minver < 3 {
					ap.Arch = ocsd.ArchV8
				} else if minver == 3 {
					ap.Arch = ocsd.ArchV8r3
				}
			}
		} else {
			return ap, false
		}

		dashPos := -1
		for i := 4; i < len(coreName); i++ {
			if coreName[i] == '-' {
				dashPos = i
				break
			}
		}

		if dashPos != 5+dotoffset {
			ap.Arch = ocsd.ArchUnknown
			return ap, false
		}

		profileIdx := 6 + dotoffset
		if profileIdx >= len(coreName) {
			ap.Arch = ocsd.ArchUnknown
			return ap, false
		}

		switch coreName[profileIdx] {
		case 'A':
			ap.Profile = ocsd.ProfileCortexA
		case 'R':
			ap.Profile = ocsd.ProfileCortexR
		case 'M':
			ap.Profile = ocsd.ProfileCortexM
		default:
			ap.Arch = ocsd.ArchUnknown
			return ap, false
		}

		return ap, true
	}

	if len(coreName) >= 8 && coreName[:4] == "ARM-" {
		if coreName[4:8] == "aa64" || coreName[4:8] == "AA64" {
			ap.Arch = ocsd.ArchAA64
			ap.Profile = ocsd.ProfileCortexA
			if len(coreName) > 9 && coreName[8] == '-' {
				if coreName[9] == 'R' {
					ap.Profile = ocsd.ProfileCortexR
				} else if coreName[9] == 'M' {
					ap.Profile = ocsd.ProfileCortexM
				}
			}
			return ap, true
		}
	}

	return ap, false
}
