package common

import (
	"bytes"
	"testing"
)

// Constants for test data (matching C++ mem_acc_test.cpp)
const (
	BLOCK_SIZE_BYTES = 4096 // 4KB blocks
	BLOCK_NUM_WORDS  = BLOCK_SIZE_BYTES / 4
	NUM_BLOCKS       = 2
)

// Test addresses for various memory spaces
const (
	TEST_ADDR_COMMON = 0x0000
	TEST_ADDR_EL1N   = 0x1000
	TEST_ADDR_EL2    = 0x2000
	TEST_ADDR_EL1S   = 0x3000
	TEST_ADDR_EL2S   = 0x4000
	TEST_ADDR_EL3    = 0x5000
	TEST_ADDR_EL1R   = 0x6000
	TEST_ADDR_EL2R   = 0x7000
	TEST_ADDR_EL3R   = 0x8000
)

// Helper to create test blocks with known content
func createTestBlock(memSpace MemorySpace, blockNum int) []byte {
	block := make([]byte, BLOCK_SIZE_BYTES)
	for i := 0; i < BLOCK_NUM_WORDS; i++ {
		// Pattern: each word contains space info, block number, and index
		word := uint32(memSpace)<<24 | uint32(blockNum)<<16 | uint32(i)
		block[i*4] = byte(word)
		block[i*4+1] = byte(word >> 8)
		block[i*4+2] = byte(word >> 16)
		block[i*4+3] = byte(word >> 24)
	}
	return block
}

// === Overlap Region Tests (matching C++ test_overlap_regions) ===

func TestMemAccMapper_OverlapDetection_SameSpace(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Create first accessor at address 0x0000
	block1 := createTestBlock(MemSpaceEL1N, 0)
	acc1 := NewMemoryBuffer(0x0000, block1)
	acc1.SetMemSpace(MemSpaceEL1N)

	err := mapper.AddAccessor(acc1, 0x0000, 0x0000+uint64(len(block1)), 0)
	if err != nil {
		t.Fatalf("Failed to add first accessor: %v", err)
	}

	// Try to add overlapping accessor in same space - should fail
	block2 := createTestBlock(MemSpaceEL1N, 1)
	acc2 := NewMemoryBuffer(0x1000, block2)
	acc2.SetMemSpace(MemSpaceEL1N)

	err = mapper.AddAccessor(acc2, 0x1000, 0x1000+uint64(len(block2)), 0)
	if err != nil {
		t.Fatalf("Failed to add non-overlapping accessor: %v", err)
	}

	// Try to add overlapping accessor in same space at 0x1000 - should fail
	block3 := createTestBlock(MemSpaceEL1N, 1)
	acc3 := NewMemoryBuffer(0x1000, block3)
	acc3.SetMemSpace(MemSpaceEL1N)

	err = mapper.AddAccessor(acc3, 0x1000, 0x1000+uint64(len(block3)), 0)
	if err == nil {
		t.Fatal("Expected error for overlapping accessor in same space")
	}
}

func TestMemAccMapper_OverlapDetection_DifferentSpaces(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Create accessor in EL1N space
	block1 := createTestBlock(MemSpaceEL1N, 0)
	acc1 := NewMemoryBuffer(0x0000, block1)
	acc1.SetMemSpace(MemSpaceEL1N)

	err := mapper.AddAccessor(acc1, 0x0000, 0x0000+uint64(len(block1)), 0)
	if err != nil {
		t.Fatalf("Failed to add first accessor: %v", err)
	}

	// Add overlapping accessor in EL1S space - should succeed
	block2 := createTestBlock(MemSpaceEL1S, 0)
	acc2 := NewMemoryBuffer(0x0000, block2)
	acc2.SetMemSpace(MemSpaceEL1S)

	err = mapper.AddAccessor(acc2, 0x0000, 0x0000+uint64(len(block2)), 0)
	if err != nil {
		t.Fatalf("Failed to add overlapping accessor in different space: %v", err)
	}
}

func TestMemAccMapper_OverlapDetection_GeneralSpace(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Create accessor in EL1N space
	block1 := createTestBlock(MemSpaceEL1N, 0)
	acc1 := NewMemoryBuffer(0x0000, block1)
	acc1.SetMemSpace(MemSpaceEL1N)

	err := mapper.AddAccessor(acc1, 0x0000, 0x0000+uint64(len(block1)), 0)
	if err != nil {
		t.Fatalf("Failed to add first accessor: %v", err)
	}

	// Create accessor in EL1S space
	block2 := createTestBlock(MemSpaceEL1S, 0)
	acc2 := NewMemoryBuffer(0x0000, block2)
	acc2.SetMemSpace(MemSpaceEL1S)

	err = mapper.AddAccessor(acc2, 0x0000, 0x0000+uint64(len(block2)), 0)
	if err != nil {
		t.Fatalf("Failed to add overlapping accessor in EL1S: %v", err)
	}

	// Try to add general S space accessor - should fail (conflicts with both EL1S and others)
	block3 := createTestBlock(MemSpaceS, 0)
	acc3 := NewMemoryBuffer(0x0000, block3)
	acc3.SetMemSpace(MemSpaceS)

	err = mapper.AddAccessor(acc3, 0x0000, 0x0000+uint64(len(block3)), 0)
	if err == nil {
		t.Fatal("Expected error for general S space overlapping with EL1S")
	}
}

// === Memory Space Tests (matching C++ test_mem_spaces) ===

func TestMemAccMapper_ReadWithSpecificSpace(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Create accessors for different memory spaces
	block1 := createTestBlock(MemSpaceEL1N, 0)
	acc1 := NewMemoryBuffer(TEST_ADDR_COMMON, block1)
	acc1.SetMemSpace(MemSpaceEL1N)

	if err := mapper.AddAccessor(acc1, TEST_ADDR_COMMON, TEST_ADDR_COMMON+uint64(len(block1)), 0); err != nil {
		t.Fatalf("Failed to add EL1N accessor: %v", err)
	}

	block2 := createTestBlock(MemSpaceEL1S, 0)
	acc2 := NewMemoryBuffer(TEST_ADDR_COMMON, block2)
	acc2.SetMemSpace(MemSpaceEL1S)

	if err := mapper.AddAccessor(acc2, TEST_ADDR_COMMON, TEST_ADDR_COMMON+uint64(len(block2)), 0); err != nil {
		t.Fatalf("Failed to add EL1S accessor: %v", err)
	}

	// Read from EL1N space
	data1 := make([]byte, 4)
	n, err := mapper.ReadMemory(TEST_ADDR_COMMON, 0, MemSpaceEL1N, data1)
	if err != nil {
		t.Fatalf("Failed to read from EL1N: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes from EL1N, got %d", n)
	}

	// Read from EL1S space
	data2 := make([]byte, 4)
	n, err = mapper.ReadMemory(TEST_ADDR_COMMON, 0, MemSpaceEL1S, data2)
	if err != nil {
		t.Fatalf("Failed to read from EL1S: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes from EL1S, got %d", n)
	}

	// Verify they contain different data
	if bytes.Equal(data1, data2) {
		t.Error("Expected different data from different memory spaces")
	}
}

func TestMemAccMapper_ReadWithGeneralSpace(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Create accessor in ANY space
	block := createTestBlock(MemSpaceANY, 0)
	acc := NewMemoryBuffer(TEST_ADDR_COMMON, block)
	acc.SetMemSpace(MemSpaceANY)

	if err := mapper.AddAccessor(acc, TEST_ADDR_COMMON, TEST_ADDR_COMMON+uint64(len(block)), 0); err != nil {
		t.Fatalf("Failed to add ANY space accessor: %v", err)
	}

	// Read from ANY space should succeed
	data := make([]byte, 4)
	n, err := mapper.ReadMemory(TEST_ADDR_COMMON, 0, MemSpaceANY, data)
	if err != nil {
		t.Fatalf("Failed to read from ANY: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes from ANY, got %d", n)
	}

	// Read from specific space through ANY accessor should also succeed
	n, err = mapper.ReadMemory(TEST_ADDR_COMMON, 0, MemSpaceEL1N, data)
	if err != nil {
		t.Fatalf("Failed to read EL1N through ANY accessor: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes through ANY, got %d", n)
	}
}

// === Callback Accessor Tests (matching C++ test_trcid_cache_mem_cb) ===

func TestMemAccMapper_CallbackAccessor(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Create a callback-based accessor
	callbackData := map[uint64][]byte{
		0x0000: []byte{0x01, 0x02, 0x03, 0x04},
		0x0004: []byte{0x05, 0x06, 0x07, 0x08},
	}

	callback := func(addr uint64, traceID uint8, space MemorySpace, data []byte) int {
		if val, ok := callbackData[addr]; ok {
			copy(data, val)
			return len(val)
		}
		return 0
	}

	acc := NewCallbackAccessor(0x0000, 0x1000, callback)
	acc.SetMemSpace(MemSpaceANY)

	if err := mapper.AddAccessor(acc, 0x0000, 0x1000, 0); err != nil {
		t.Fatalf("Failed to add callback accessor: %v", err)
	}

	// Read through callback
	data := make([]byte, 4)
	n, err := mapper.ReadMemory(0x0000, 0, MemSpaceANY, data)
	if err != nil {
		t.Fatalf("Failed to read through callback: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes from callback, got %d", n)
	}
	if !bytes.Equal(data, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("Callback data mismatch: got %v", data)
	}
}

func TestMemAccMapper_CallbackAccessor_TraceIDSpecific(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Create trace-ID specific callbacks with data embedded
	callback0 := func(addr uint64, traceID uint8, space MemorySpace, data []byte) int {
		// Callback for trace ID 0
		if addr == 0x0000 {
			copy(data, []byte{0xAA, 0xBB, 0xCC, 0xDD})
			return 4
		}
		return 0
	}

	callback1 := func(addr uint64, traceID uint8, space MemorySpace, data []byte) int {
		// Callback for trace ID 1
		if addr == 0x1000 {
			copy(data, []byte{0x11, 0x22, 0x33, 0x44})
			return 4
		}
		return 0
	}

	// Add accessor for trace ID 0 at address 0x0000
	acc1 := NewCallbackAccessor(0x0000, 0x1000, callback0)
	acc1.SetMemSpace(MemSpaceANY)
	mapper.AddAccessor(acc1, 0x0000, 0x1000, 0)

	// Add accessor for trace ID 1 at a different address range
	acc2 := NewCallbackAccessor(0x1000, 0x2000, callback1)
	acc2.SetMemSpace(MemSpaceANY)
	mapper.AddAccessor(acc2, 0x1000, 0x2000, 1)

	// Read with trace ID 0
	data0 := make([]byte, 4)
	n, err := mapper.ReadMemory(0x0000, 0, MemSpaceANY, data0)
	if err != nil {
		t.Errorf("Trace ID 0 read error: %v", err)
	}
	if n != 4 {
		t.Errorf("Trace ID 0 expected 4 bytes, got %d", n)
	}
	if !bytes.Equal(data0, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Errorf("Trace ID 0 data mismatch: got %v", data0)
	}

	// Read with trace ID 1
	data1 := make([]byte, 4)
	n, err = mapper.ReadMemory(0x1000, 1, MemSpaceANY, data1)
	if err != nil {
		t.Errorf("Trace ID 1 read error: %v", err)
	}
	if n != 4 {
		t.Errorf("Trace ID 1 expected 4 bytes, got %d", n)
	}
	if !bytes.Equal(data1, []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("Trace ID 1 data mismatch: got %v", data1)
	}
}

// === Basic Buffer Tests ===

func TestMemAccMapper_MultipleBuffers(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	// Add multiple buffers at different addresses
	block1 := createTestBlock(MemSpaceEL1N, 0)
	acc1 := NewMemoryBuffer(0x0000, block1)
	acc1.SetMemSpace(MemSpaceEL1N)
	mapper.AddAccessor(acc1, 0x0000, 0x0000+uint64(len(block1)), 0)

	block2 := createTestBlock(MemSpaceEL1N, 1)
	acc2 := NewMemoryBuffer(0x1000, block2)
	acc2.SetMemSpace(MemSpaceEL1N)
	mapper.AddAccessor(acc2, 0x1000, 0x1000+uint64(len(block2)), 0)

	// Read from first buffer
	data1 := make([]byte, 4)
	n, err := mapper.ReadMemory(0x0100, 0, MemSpaceEL1N, data1)
	if err != nil || n != 4 {
		t.Fatalf("Failed to read from buffer 1: %v", err)
	}

	// Read from second buffer
	data2 := make([]byte, 4)
	n, err = mapper.ReadMemory(0x1100, 0, MemSpaceEL1N, data2)
	if err != nil || n != 4 {
		t.Fatalf("Failed to read from buffer 2: %v", err)
	}

	// Verify they're from different blocks
	if bytes.Equal(data1, data2) {
		t.Error("Expected different data from different blocks")
	}
}

func TestMemAccMapper_RemoveAccessor(t *testing.T) {
	mapper := NewMemoryAccessorMapper()

	block := createTestBlock(MemSpaceEL1N, 0)
	acc := NewMemoryBuffer(0x0000, block)
	acc.SetMemSpace(MemSpaceEL1N)

	mapper.AddAccessor(acc, 0x0000, 0x0000+uint64(len(block)), 0)

	// Should be able to read
	data := make([]byte, 4)
	_, err := mapper.ReadMemory(0x0000, 0, MemSpaceEL1N, data)
	if err != nil {
		t.Fatalf("Failed to read before removal: %v", err)
	}

	// Remove accessor
	if err := mapper.RemoveAccessor(acc); err != nil {
		t.Fatalf("Failed to remove accessor: %v", err)
	}

	// Should not be able to read anymore
	_, err = mapper.ReadMemory(0x0000, 0, MemSpaceEL1N, data)
	if err == nil {
		t.Fatal("Expected error after removing accessor")
	}
}

func TestMemAccMapper_MemorySpaceMatching(t *testing.T) {
	tests := []struct {
		name     string
		space1   MemorySpace
		space2   MemorySpace
		expected bool
	}{
		{"EL1N matches EL1N", MemSpaceEL1N, MemSpaceEL1N, true},
		{"EL1N matches N", MemSpaceEL1N, MemSpaceN, true},
		{"N matches EL1N", MemSpaceN, MemSpaceEL1N, true},
		{"ANY matches EL1N", MemSpaceANY, MemSpaceEL1N, true},
		{"EL1N matches ANY", MemSpaceEL1N, MemSpaceANY, true},
		{"EL1N does not match EL1S", MemSpaceEL1N, MemSpaceEL1S, false},
		{"S matches EL1S", MemSpaceS, MemSpaceEL1S, true},
		{"EL1S matches S", MemSpaceEL1S, MemSpaceS, true},
		{"R matches EL1R", MemSpaceR, MemSpaceEL1R, true},
		{"EL1R matches R", MemSpaceEL1R, MemSpaceR, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.space1.InMemSpace(tt.space2)
			if result != tt.expected {
				t.Errorf("InMemSpace(%s, %s) = %v, expected %v",
					tt.space1.String(), tt.space2.String(), result, tt.expected)
			}
		})
	}
}
