package common

import (
	"maps"
	"strings"

	"opencsd/internal/ocsd"
)

var defaultCoreMap = map[string]ocsd.ArchProfile{
	// Cortex-A Series
	"Cortex-A77": {Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA},
	"Cortex-A76": {Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA},
	"Cortex-A75": {Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA},
	"Cortex-A73": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA},
	"Cortex-A72": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA},
	"Cortex-A65": {Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA},
	"Cortex-A57": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA},
	"Cortex-A55": {Arch: ocsd.ArchV8r3, Profile: ocsd.ProfileCortexA},
	"Cortex-A53": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA},
	"Cortex-A35": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA},
	"Cortex-A32": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexA},
	"Cortex-A17": {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA},
	"Cortex-A15": {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA},
	"Cortex-A12": {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA},
	"Cortex-A9":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA},
	"Cortex-A8":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA},
	"Cortex-A7":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA},
	"Cortex-A5":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexA},

	// Cortex-R Series
	"Cortex-R52": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexR},
	"Cortex-R8":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR},
	"Cortex-R7":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR},
	"Cortex-R5":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR},
	"Cortex-R4":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexR},

	// Cortex-M Series
	"Cortex-M55": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM},
	"Cortex-M33": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM},
	"Cortex-M23": {Arch: ocsd.ArchV8, Profile: ocsd.ProfileCortexM},
	"Cortex-M4":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM},
	"Cortex-M3":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM},
	"Cortex-M0+": {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM},
	"Cortex-M0":  {Arch: ocsd.ArchV7, Profile: ocsd.ProfileCortexM},
}

// CoreArchProfileMap maps core names to architecture profiles.
type CoreArchProfileMap struct {
	coreMap map[string]ocsd.ArchProfile
}

// NewCoreArchProfileMap creates a new map.
func NewCoreArchProfileMap() *CoreArchProfileMap {
	m := make(map[string]ocsd.ArchProfile, len(defaultCoreMap))
	maps.Copy(m, defaultCoreMap)

	return &CoreArchProfileMap{coreMap: m}
}

// ArchProfile returns the architecture profile for a given core name.
func (m *CoreArchProfileMap) ArchProfile(coreName string) (ocsd.ArchProfile, bool) {
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

	if rest, ok := strings.CutPrefix(coreName, "ARMv"); ok {
		if len(rest) == 0 || rest[0] < '0' || rest[0] > '9' {
			return ap, false
		}

		majver := int(rest[0] - '0')
		minver := 0
		profileOffset := 1

		if strings.HasPrefix(rest[1:], ".") {
			if len(rest) < 3 || rest[2] < '0' || rest[2] > '9' {
				return ap, false
			}
			minver = int(rest[2] - '0')
			profileOffset = 3
		} else if strings.IndexByte(rest, '.') >= 0 {
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

		if len(rest) <= profileOffset || rest[profileOffset] != '-' {
			ap.Arch = ocsd.ArchUnknown
			return ap, false
		}
		profileIdx := profileOffset + 1
		if profileIdx >= len(rest) {
			ap.Arch = ocsd.ArchUnknown
			return ap, false
		}

		switch rest[profileIdx] {
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

	if rest, ok := strings.CutPrefix(coreName, "ARM-"); ok {
		if strings.HasPrefix(rest, "aa64") || strings.HasPrefix(rest, "AA64") {
			ap.Arch = ocsd.ArchAA64
			ap.Profile = ocsd.ProfileCortexA
			if len(rest) > 5 && rest[4] == '-' {
				if rest[5] == 'R' {
					ap.Profile = ocsd.ProfileCortexR
				} else if rest[5] == 'M' {
					ap.Profile = ocsd.ProfileCortexM
				}
			}
			return ap, true
		}
	}

	return ap, false
}
