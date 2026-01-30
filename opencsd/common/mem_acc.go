package common

// MemoryAccessor defines an interface for reading memory during trace decoding.
// This allows decoders to read instruction opcodes at specific addresses to
// determine branch targets and instruction behavior.
//
// Implementations can provide:
// - In-memory buffers loaded from snapshot .bin files
// - Mocked memory for unit tests
// - Live memory access for online decoding scenarios
type MemoryAccessor interface {
	// ReadMemory reads bytes from memory at the specified address.
	// Returns the number of bytes successfully read and any error encountered.
	//
	// Parameters:
	//   addr: The memory address to read from
	//   data: Buffer to store the read bytes
	//
	// Returns:
	//   int: Number of bytes actually read (may be less than len(data) if
	//        address is at the end of a memory region)
	//   error: nil on success, or an error if the address is inaccessible
	//
	// Implementations should:
	// - Return partial reads when the requested range exceeds available memory
	// - Return an error for completely invalid addresses
	// - Support unaligned accesses (common in ARM instruction sets)
	ReadMemory(addr uint64, data []byte) (int, error)

	// ReadTargetMemory reads bytes from memory at the specified address.
	// This mirrors the C++ naming convention used by the OpenCSD library.
	// Implementations may delegate this to ReadMemory.
	ReadTargetMemory(addr uint64, data []byte) (int, error)
}
