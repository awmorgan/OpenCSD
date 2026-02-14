package memacc

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Constants from C++
const (
	numBlocks     = 2
	blockNumWords = 8192
	blockSize     = 4 * blockNumWords
)

// Global test data blocks
var (
	el01NSBlocks  [numBlocks][]byte
	el2NSBlocks   [numBlocks][]byte
	el01SBlocks   [numBlocks][]byte
	el2SBlocks    [numBlocks][]byte
	el3Blocks     [numBlocks][]byte
	el01RBlocks   [numBlocks][]byte
	el2RBlocks    [numBlocks][]byte
	el3RootBlocks [numBlocks][]byte
)

func init() {
	initTestBlocks()
}

func blockVal(memSpace MemSpace, blockNum int, index int) uint32 {
	return (uint32(memSpace) << 24) | (uint32(blockNum) << 16) | uint32(index)
}

func populateBlock(memSpace MemSpace, blocks *[numBlocks][]byte) {
	for i := 0; i < numBlocks; i++ {
		buf := new(bytes.Buffer)
		for j := 0; j < blockNumWords; j++ {
			val := blockVal(memSpace, i, j)
			binary.Write(buf, binary.LittleEndian, val)
		}
		blocks[i] = buf.Bytes()
	}
}

func initTestBlocks() {
	populateBlock(MemSpaceEL1N, &el01NSBlocks)
	populateBlock(MemSpaceEL2, &el2NSBlocks)
	populateBlock(MemSpaceEL1S, &el01SBlocks)
	populateBlock(MemSpaceEL2S, &el2SBlocks)
	populateBlock(MemSpaceEL3, &el3Blocks)
	populateBlock(MemSpaceEL1R, &el01RBlocks)
	populateBlock(MemSpaceEL2R, &el2RBlocks)
	populateBlock(MemSpaceRoot, &el3RootBlocks)
}

// TestOverlapRegions matches test_overlap_regions in C++
func TestOverlapRegions(t *testing.T) {
	mapper := NewMapper()
	defer mapper.RemoveAllAccessors()

	var err error

	// Add single accessor
	acc1 := NewBufferAccessor(0x0000, el01NSBlocks[0], MemSpaceEL1N)
	if err = mapper.AddAccessor(acc1, 0); err != nil {
		t.Errorf("Failed to set memory accessor: %v", err)
	}

	// Overlapping region - same memory space (Should Error)
	acc2 := NewBufferAccessor(0x1000, el01NSBlocks[1], MemSpaceEL1N)
	if err = mapper.AddAccessor(acc2, 0); err != ErrMemAccOverlap {
		t.Errorf("Expected ErrMemAccOverlap, got %v", err)
	}

	// Non-overlapping region - same memory space (Should OK)
	acc2Fixed := NewBufferAccessor(0x8000, el01NSBlocks[1], MemSpaceEL1N)
	if err = mapper.AddAccessor(acc2Fixed, 0); err != nil {
		t.Errorf("Failed to set non-overlapping accessor: %v", err)
	}

	// Overlapping region - different memory space (Should OK)
	acc3 := NewBufferAccessor(0x0000, el01SBlocks[0], MemSpaceEL1S)
	if err = mapper.AddAccessor(acc3, 0); err != nil {
		t.Errorf("Failed to set overlapping accessor in diff space: %v", err)
	}

	// Overlapping region - more general memory space (Should Error)
	acc4 := NewBufferAccessor(0x0000, el2SBlocks[0], MemSpaceS)
	if err = mapper.AddAccessor(acc4, 0); err != ErrMemAccOverlap {
		t.Errorf("Expected ErrMemAccOverlap for general S accessor, got %v", err)
	}
}

// TestSplitBufferAccess is inspired by mem_buff_demo.cpp.
// It tests splitting a single logical memory image into two adjacent accessors.
func TestSplitBufferAccess(t *testing.T) {
	mapper := NewMapper()
	defer mapper.RemoveAllAccessors()

	// Create a 1KB buffer
	totalSize := 1024
	fullData := make([]byte, totalSize)
	for i := 0; i < totalSize; i++ {
		fullData[i] = byte(i & 0xFF)
	}

	// Split into two halves
	splitPoint := 512
	part1 := fullData[:splitPoint]
	part2 := fullData[splitPoint:]

	startAddr := uint64(0x1000)
	midAddr := startAddr + uint64(splitPoint)

	// Add Accessor 1: [0x1000 - 0x11FF]
	acc1 := NewBufferAccessor(startAddr, part1, MemSpaceAny)
	if err := mapper.AddAccessor(acc1, 0); err != nil {
		t.Fatalf("Failed to add part 1: %v", err)
	}

	// Add Accessor 2: [0x1200 - 0x13FF]
	acc2 := NewBufferAccessor(midAddr, part2, MemSpaceAny)
	if err := mapper.AddAccessor(acc2, 0); err != nil {
		t.Fatalf("Failed to add part 2: %v", err)
	}

	// Verify read at start of Part 1
	val, err := mapper.ReadTargetMemory(startAddr, 0, MemSpaceAny, 4)
	if err != nil {
		t.Errorf("Read at start failed: %v", err)
	}
	// Expected: 0x03020100 (Little Endian of bytes 0,1,2,3)
	expectedStart := uint32(0x03020100)
	if val != expectedStart {
		t.Errorf("Start value mismatch. Got %x, want %x", val, expectedStart)
	}

	// Verify read at start of Part 2 (Boundary check)
	// midAddr is 0x1200. Bytes should correspond to fullData[512]
	val, err = mapper.ReadTargetMemory(midAddr, 0, MemSpaceAny, 4)
	if err != nil {
		t.Errorf("Read at boundary failed: %v", err)
	}
	// fullData[512] = 0 (since 512 & 0xFF == 0). Sequence: 00 01 02 03
	expectedMid := uint32(0x03020100)
	if val != expectedMid {
		t.Errorf("Mid value mismatch. Got %x, want %x", val, expectedMid)
	}

	// Verify read STRADDLING the boundary
	// Read 4 bytes starting 2 bytes before the split.
	// Accessors in OpenCSD do NOT automatically stitch reads across boundaries.
	// The mapper finds the *first* accessor covering the start address and reads what it can from it.
	// So, reading 4 bytes at (midAddr - 2) should return the last 2 bytes of Acc1, and likely fail the "4 byte check" in ReadTargetMemory wrapper.

	// Bytes at 510, 511 are [0xFE, 0xFF].
	// The Mapper.ReadTargetMemory expects 4 full bytes or it errors.
	_, err = mapper.ReadTargetMemory(midAddr-2, 0, MemSpaceAny, 4)
	if err == nil {
		t.Errorf("Expected error when reading across non-contiguous accessor boundary, but got success")
	} else if err.Error() != "insufficient data read" {
		t.Errorf("Expected 'insufficient data read' error, got: %v", err)
	}
}

// Data structures for Callback Test
type testRange struct {
	sAddr    uint64
	size     uint32
	buffer   []byte
	memSpace MemSpace
	trcID    uint8
}

var accCallbackCount int

// Callback implementation
func testMemAccCB(ctx interface{}, addr uint64, space MemSpace, trcID uint8, reqBytes uint32) ([]byte, error) {
	ranges := ctx.([]testRange)
	accCallbackCount++

	for _, r := range ranges {
		spaceMatch := (uint32(space) & uint32(r.memSpace)) != 0

		if spaceMatch && trcID == r.trcID {
			if addr >= r.sAddr && addr < (r.sAddr+uint64(r.size)) {
				offset := addr - r.sAddr
				bytesRead := reqBytes

				if uint64(reqBytes) > (uint64(r.size) - offset) {
					bytesRead = uint32(uint64(r.size) - offset)
				}

				out := make([]byte, bytesRead)
				copy(out, r.buffer[offset:offset+uint64(bytesRead)])
				return out, nil
			}
		}
	}
	return nil, nil // Not found
}

// TestTrcIDCacheMemCB matches test_trcid_cache_mem_cb in C++
func TestTrcIDCacheMemCB(t *testing.T) {
	mapper := NewMapper()
	defer mapper.RemoveAllAccessors()
	mapper.EnableCaching(true)

	accCallbackCount = 0

	// Set up ranges
	ranges := []testRange{
		{0x0000, blockSize, el01NSBlocks[0], MemSpaceEL1N, 0x10},
		{0x0000, blockSize, el01NSBlocks[1], MemSpaceEL1N, 0x11},
		{0x8000, blockSize, el2NSBlocks[0], MemSpaceEL2, 0x10},
		{0x10000, blockSize, el2NSBlocks[1], MemSpaceEL2, 0x11},
		{0x0000, blockSize, el01RBlocks[0], MemSpaceEL1R, 0x10},
		{0x0000, blockSize, el2RBlocks[0], MemSpaceEL2R, 0x11},
	}

	// Create CB Accessor covering everything
	cbAcc := NewCBAccessor(0, 0xFFFFFFFF, MemSpaceAny)
	cbAcc.SetCB(testMemAccCB, ranges)

	if err := mapper.AddAccessor(cbAcc, 0); err != nil {
		t.Fatalf("Failed to add CB accessor: %v", err)
	}

	readAndCheck := func(t *testing.T, rangeIdx int, offset uint64, expectCB bool) {
		t.Helper()
		r := ranges[rangeIdx]
		addr := r.sAddr + offset

		prevCount := accCallbackCount

		// In C++ test, it reads 4 bytes into a uint32.
		val, err := mapper.ReadTargetMemory(addr, r.trcID, MemSpaceEL1N, 4)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		// Check value
		expectedVal := binary.LittleEndian.Uint32(r.buffer[offset : offset+4])
		if val != expectedVal {
			t.Errorf("Value mismatch: got 0x%x, want 0x%x", val, expectedVal)
		}

		// Check callback occurrence
		cbOccurred := accCallbackCount != prevCount
		if expectCB && !cbOccurred {
			t.Errorf("Expected callback did not occur")
		}
		if !expectCB && cbOccurred {
			t.Errorf("Unexpected callback occurred")
		}
	}

	// Initial read - should callback and load cache
	readAndCheck(t, 0, 0, true)

	// Next read - should not callback (cached)
	readAndCheck(t, 0, 0x10, false)

	// Different CPU, same address - should callback (new cache entry)
	readAndCheck(t, 1, 0x10, true)

	// Different CPU, same address - cached
	readAndCheck(t, 1, 0x10, false)
}

// TestMemSpaces matches test_mem_spaces in C++
func TestMemSpaces(t *testing.T) {
	mapper := NewMapper()
	defer mapper.RemoveAllAccessors()
	mapper.EnableCaching(true)

	// Helper to add accessor
	addAcc := func(addr uint64, data []byte, space MemSpace) {
		acc := NewBufferAccessor(addr, data, space)
		if err := mapper.AddAccessor(acc, 0); err != nil {
			t.Fatalf("Failed to add accessor: %v", err)
		}
	}

	// Test addresses
	testAddrCommon := uint64(0x000000)
	testAddrEL1N := uint64(0x008000)
	testAddrEL2 := uint64(0x010000)
	testAddrEL1S := uint64(0x018000)
	testAddrEL2S := uint64(0x020000)
	testAddrEL3 := uint64(0x028000)
	testAddrEL1R := uint64(0x030000)
	testAddrEL2R := uint64(0x038000)
	testAddrEL3R := uint64(0x040000)

	// Setup accessors
	addAcc(testAddrCommon, el01NSBlocks[0], MemSpaceEL1N)
	addAcc(testAddrEL1N, el01NSBlocks[1], MemSpaceEL1N)
	addAcc(testAddrCommon, el2NSBlocks[0], MemSpaceEL2)
	addAcc(testAddrEL2, el2NSBlocks[1], MemSpaceEL2)
	addAcc(testAddrCommon, el01SBlocks[0], MemSpaceEL1S)
	addAcc(testAddrEL1S, el01SBlocks[1], MemSpaceEL1S)
	addAcc(testAddrCommon, el2SBlocks[0], MemSpaceEL2S)
	addAcc(testAddrEL2S, el2SBlocks[1], MemSpaceEL2S)
	addAcc(testAddrCommon, el3Blocks[0], MemSpaceEL3)
	addAcc(testAddrEL3, el3Blocks[1], MemSpaceEL3)
	addAcc(testAddrCommon, el01RBlocks[0], MemSpaceEL1R)
	addAcc(testAddrEL1R, el01RBlocks[1], MemSpaceEL1R)
	addAcc(testAddrCommon, el2RBlocks[0], MemSpaceEL2R)
	addAcc(testAddrEL2R, el2RBlocks[1], MemSpaceEL2R)
	addAcc(testAddrCommon, el3RootBlocks[0], MemSpaceRoot)
	addAcc(testAddrEL3R, el3RootBlocks[1], MemSpaceRoot)

	// Table driven verification
	tests := []struct {
		name        string
		addr        uint64
		data        []byte
		checkSpaces []MemSpace
	}{
		{"EL1N", testAddrEL1N, el01NSBlocks[1], []MemSpace{MemSpaceEL1N, MemSpaceN, MemSpaceAny}},
		{"EL2", testAddrEL2, el2NSBlocks[1], []MemSpace{MemSpaceEL2, MemSpaceN, MemSpaceAny}},
		{"EL1S", testAddrEL1S, el01SBlocks[1], []MemSpace{MemSpaceEL1S, MemSpaceS, MemSpaceAny}},
		{"EL2S", testAddrEL2S, el2SBlocks[1], []MemSpace{MemSpaceEL2S, MemSpaceS, MemSpaceAny}},
		{"EL3", testAddrEL3, el3Blocks[1], []MemSpace{MemSpaceEL3, MemSpaceS, MemSpaceAny}},
		{"EL1R", testAddrEL1R, el01RBlocks[1], []MemSpace{MemSpaceEL1R, MemSpaceR, MemSpaceAny}},
		{"EL2R", testAddrEL2R, el2RBlocks[1], []MemSpace{MemSpaceEL2R, MemSpaceR, MemSpaceAny}},
		{"Root", testAddrEL3R, el3RootBlocks[1], []MemSpace{MemSpaceRoot, MemSpaceAny}},
	}

	check := func(addr uint64, data []byte, space MemSpace) {
		t.Helper()
		val, err := mapper.ReadTargetMemory(addr, 0, space, 4)
		if err != nil {
			t.Fatalf("Read failed at 0x%x (Space %v): %v", addr, space, err)
		}
		expected := binary.LittleEndian.Uint32(data[:4])
		if val != expected {
			t.Errorf("Mismatch at 0x%x (Space %v): got 0x%x, want 0x%x", addr, space, val, expected)
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, space := range tc.checkSpaces {
				check(tc.addr, tc.data, space)
			}
		})
	}
}

// TestFileAccessor checks the new FileAccessor implementation.
func TestFileAccessor(t *testing.T) {
	// Create a temp binary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_mem.bin")

	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 255)
	}
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	mapper := NewMapper()
	defer mapper.RemoveAllAccessors()

	// Basic File Access
	acc1, err := NewFileAccessor(tmpFile, 0x1000, 0, 0, MemSpaceAny)
	if err != nil {
		t.Fatalf("NewFileAccessor failed: %v", err)
	}
	if err := mapper.AddAccessor(acc1, 0); err != nil {
		t.Fatalf("AddAccessor failed: %v", err)
	}

	val, err := mapper.ReadTargetMemory(0x1000, 0, MemSpaceAny, 4)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	expected := binary.LittleEndian.Uint32(data[0:4])
	if val != expected {
		t.Errorf("File read mismatch: got %x, want %x", val, expected)
	}

	// Offset Region Test
	acc2, err := NewFileAccessor(tmpFile, 0x5000, 0, 10, MemSpaceAny)
	if err != nil {
		t.Fatalf("NewFileAccessor 2 failed: %v", err)
	}

	err = acc2.AddOffsetRange(0x8000, 16, 100)
	if err != nil {
		t.Fatalf("AddOffsetRange failed: %v", err)
	}

	if err := mapper.AddAccessor(acc2, 0); err != nil {
		t.Fatalf("AddAccessor 2 failed: %v", err)
	}

	valRegion, err := mapper.ReadTargetMemory(0x8000, 0, MemSpaceAny, 4)
	if err != nil {
		t.Fatalf("Read region failed: %v", err)
	}
	expectedRegion := binary.LittleEndian.Uint32(data[100:104])
	if valRegion != expectedRegion {
		t.Errorf("Region read mismatch: got %x, want %x", valRegion, expectedRegion)
	}
}
