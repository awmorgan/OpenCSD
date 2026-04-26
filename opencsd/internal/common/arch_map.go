package common

import (
	"maps"
	"strconv"
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

var unknownArchProfile = ocsd.ArchProfile{Arch: ocsd.ArchUnknown, Profile: ocsd.ProfileUnknown}

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

	return getPatternMatchCoreName(coreName)
}

func getPatternMatchCoreName(coreName string) (ocsd.ArchProfile, bool) {
	if rest, ok := strings.CutPrefix(coreName, "ARMv"); ok {
		return parseARMvCoreName(rest)
	}
	if rest, ok := strings.CutPrefix(coreName, "ARM-"); ok {
		return parseARMDashCoreName(rest)
	}
	return unknownArchProfile, false
}

func parseARMvCoreName(rest string) (ocsd.ArchProfile, bool) {
	version, profile, ok := strings.Cut(rest, "-")
	if !ok || profile == "" {
		return unknownArchProfile, false
	}

	major, minor, ok := parseARMVersion(version)
	if !ok {
		return unknownArchProfile, false
	}

	ap := ocsd.ArchProfile{}
	if !setProfileFromByte(&ap, profile[0]) {
		return unknownArchProfile, false
	}
	if !setArchFromARMVersion(&ap, major, minor) {
		return unknownArchProfile, false
	}
	return ap, true
}

func parseARMDashCoreName(rest string) (ocsd.ArchProfile, bool) {
	archName, profile, hasProfile := strings.Cut(rest, "-")
	if !strings.EqualFold(archName, "aa64") {
		return unknownArchProfile, false
	}

	ap := ocsd.ArchProfile{Arch: ocsd.ArchAA64, Profile: ocsd.ProfileCortexA}
	if !hasProfile || profile == "" {
		return ap, true
	}

	switch profile[0] {
	case 'R':
		ap.Profile = ocsd.ProfileCortexR
	case 'M':
		ap.Profile = ocsd.ProfileCortexM
	}
	return ap, true
}

func parseARMVersion(version string) (major, minor int, ok bool) {
	majorPart, minorPart, hasMinor := strings.Cut(version, ".")

	major, err := strconv.Atoi(majorPart)
	if err != nil || major < 0 {
		return 0, 0, false
	}

	if !hasMinor {
		return major, 0, true
	}

	minor, err = strconv.Atoi(minorPart)
	if err != nil || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

func setArchFromARMVersion(ap *ocsd.ArchProfile, major, minor int) bool {
	switch {
	case major == 7:
		ap.Arch = ocsd.ArchV7
	case major == 8 && minor < 3:
		ap.Arch = ocsd.ArchV8
	case major == 8 && minor == 3:
		ap.Arch = ocsd.ArchV8r3
	case major >= 8:
		ap.Arch = ocsd.ArchAA64
	default:
		return false
	}
	return true
}

func setProfileFromByte(ap *ocsd.ArchProfile, profile byte) bool {
	switch profile {
	case 'A':
		ap.Profile = ocsd.ProfileCortexA
	case 'R':
		ap.Profile = ocsd.ProfileCortexR
	case 'M':
		ap.Profile = ocsd.ProfileCortexM
	default:
		return false
	}
	return true
}
