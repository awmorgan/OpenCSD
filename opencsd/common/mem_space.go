package common

// MemorySpace represents CPU memory space types used in trace decoding.
// Memory spaces form a hierarchy where general spaces match specific spaces:
// - ANY matches all spaces
// - N matches EL1N, EL2N (Secure/Non-secure extension)
// - S matches EL1S, EL2S, EL3 (Secure extension)
// - R matches EL1R, EL2R (Root extension)
// Individual spaces (EL1N, EL2, etc.) match only themselves
type MemorySpace uint8

const (
	// Individual memory spaces - implementation defined extensions
	MemSpaceEL1N MemorySpace = 1 << iota // Exception Level 1 Non-secure (bit 0)
	MemSpaceEL2                          // Exception Level 2 Non-secure (bit 1)
	MemSpaceEL1S                         // Exception Level 1 Secure (bit 2)
	MemSpaceEL2S                         // Exception Level 2 Secure (bit 3)
	MemSpaceEL3                          // Exception Level 3 Secure (bit 4)
	MemSpaceEL1R                         // Exception Level 1 Root (bit 5)
	MemSpaceEL2R                         // Exception Level 2 Root (bit 6)
	MemSpaceROOT                         // Reserved/Root (bit 7)

	// Hierarchical spaces - match multiple individual spaces
	MemSpaceN   MemorySpace = MemSpaceEL1N | MemSpaceEL2                // Secure/Non-secure extension
	MemSpaceS   MemorySpace = MemSpaceEL1S | MemSpaceEL2S | MemSpaceEL3 // Secure extension
	MemSpaceR   MemorySpace = MemSpaceEL1R | MemSpaceEL2R               // Root extension
	MemSpaceANY MemorySpace = 0xFF                                      // Any memory space
)

// InMemSpace returns true if this space matches the given space.
// Matches if both spaces have overlapping bits (bitwise AND non-zero).
func (m MemorySpace) InMemSpace(space MemorySpace) bool {
	return (m & space) != 0
}

// String returns a human-readable representation of the memory space.
func (m MemorySpace) String() string {
	switch m {
	case MemSpaceEL1N:
		return "EL1N"
	case MemSpaceEL2:
		return "EL2"
	case MemSpaceEL1S:
		return "EL1S"
	case MemSpaceEL2S:
		return "EL2S"
	case MemSpaceEL3:
		return "EL3"
	case MemSpaceEL1R:
		return "EL1R"
	case MemSpaceEL2R:
		return "EL2R"
	case MemSpaceROOT:
		return "ROOT"
	case MemSpaceN:
		return "N"
	case MemSpaceS:
		return "S"
	case MemSpaceR:
		return "R"
	case MemSpaceANY:
		return "ANY"
	default:
		return "UNKNOWN"
	}
}
