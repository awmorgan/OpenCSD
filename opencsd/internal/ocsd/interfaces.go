package ocsd

// FnMemAccCB is the callback function definition for callback function memory accessor type.
//
// When using callback memory accessor, the decoder will call this function to obtain the
// memory at the address for the current opcodes. The memory space will represent the current
// exception level and security context of the traced code.
//
// Return the number of bytes read, which can be less than the amount requested if this would take the
// access address outside the range of addresses defined when this callback was registered with the decoder.
//
// Return 0 bytes if start address out of covered range, or memory space is not one of those defined as supported
// when the callback was registered.
type FnMemAccCB func(pContext any, address VAddr, memSpace MemSpaceAcc, reqBytes uint32, byteBuffer []byte) uint32

// FnMemAccIDCB is the callback function definition for callback function memory accessor type.
//
// When using callback memory accessor, the decoder will call this function to obtain the
// memory at the address for the current opcodes. The memory space will represent the current
// exception level and security context of the traced code.
//
// Return the number of bytes read, which can be less than the amount requested if this would take the
// access address outside the range of addresses defined when this callback was registered with the decoder.
//
// Return 0 bytes if start address out of covered range, or memory space is not one of those defined as supported
// when the callback was registered.
type FnMemAccIDCB func(pContext any, address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, byteBuffer []byte) uint32
