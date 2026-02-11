package memacc

import (
	"bytes"
	"encoding/binary"
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

func TestOverlapRegions(t *testing.T) {
	mapper := NewMapper()
	defer mapper.RemoveAllAccessors()

	var err error

	// Add single accessor
	acc1 := &BufferAccessor{}
	acc1.InitAccessor(0x0000, el01NSBlocks[0])
	acc1.SetMemSpace(MemSpaceEL1N)
	if err = mapper.AddAccessor(acc1, 0); err != nil {
		t.Errorf("Failed to set memory accessor: %v", err)
	}

	// Overlapping region - same memory space (Should Error)
	acc2 := &BufferAccessor{}
	acc2.InitAccessor(0x1000, el01NSBlocks[1])
	acc2.SetMemSpace(MemSpaceEL1N)
	if err = mapper.AddAccessor(acc2, 0); err != ErrMemAccOverlap {
		t.Errorf("Expected ErrMemAccOverlap, got %v", err)
	}

	// Non-overlapping region - same memory space (Should OK)
	acc2.SetRange(0x8000, 0x8000+uint64(blockSize)-1)
	if err = mapper.AddAccessor(acc2, 0); err != nil {
		t.Errorf("Failed to set non-overlapping accessor: %v", err)
	}

	// Overlapping region - different memory space (Should OK)
	acc3 := &BufferAccessor{}
	acc3.InitAccessor(0x0000, el01SBlocks[0])
	acc3.SetMemSpace(MemSpaceEL1S)
	if err = mapper.AddAccessor(acc3, 0); err != nil {
		t.Errorf("Failed to set overlapping accessor in diff space: %v", err)
	}

	// Overlapping region - more general memory space (Should Error)
	acc4 := &BufferAccessor{}
	acc4.InitAccessor(0x0000, el2SBlocks[0])
	acc4.SetMemSpace(MemSpaceS) // General S space
	if err = mapper.AddAccessor(acc4, 0); err != ErrMemAccOverlap {
		t.Errorf("Expected ErrMemAccOverlap for general S accessor, got %v", err)
	}
}

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
		// Check space overlap
		if (uint32(space)&uint32(r.memSpace)) != 0 && trcID == r.trcID {
			if addr >= r.sAddr && addr < (r.sAddr+uint64(r.size)) {
				offset := addr - r.sAddr
				bytesRead := reqBytes
				if uint64(reqBytes) > (uint64(r.size) - offset) {
					bytesRead = uint32(uint64(r.size) - offset)
				}
				return r.buffer[offset : offset+uint64(bytesRead)], nil
			}
		}
	}
	return nil, nil // Not found
}

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

	cbAcc := &CBAccessor{}
	cbAcc.InitAccessor(0, 0xFFFFFFFF, MemSpaceAny)
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

func TestMemSpaces(t *testing.T) {
	mapper := NewMapper()
	defer mapper.RemoveAllAccessors()
	mapper.EnableCaching(true)

	// Helper to add accessor
	addAcc := func(addr uint64, data []byte, space MemSpace) {
		acc := &BufferAccessor{}
		acc.InitAccessor(addr, data)
		acc.SetMemSpace(space)
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

	// Helper for checking values
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
	checkOffset := func(addr uint64, data []byte, offset uint64, space MemSpace) {
		t.Helper()
		val, err := mapper.ReadTargetMemory(addr+offset, 0, space, 4)
		if err != nil {
			t.Fatalf("Read failed at 0x%x (Space %v): %v", addr+offset, space, err)
		}
		expected := binary.LittleEndian.Uint32(data[offset : offset+4])
		if val != expected {
			t.Errorf("Mismatch at 0x%x (Space %v): got 0x%x, want 0x%x", addr+offset, space, val, expected)
		}
	}

	// Test EL1N
	t.Log("Test EL1N registered block")
	check(testAddrCommon, el01NSBlocks[0], MemSpaceEL1N)
	check(testAddrEL1N, el01NSBlocks[1], MemSpaceEL1N)
	check(testAddrEL1N, el01NSBlocks[1], MemSpaceN)
	check(testAddrEL1N, el01NSBlocks[1], MemSpaceAny)

	// Test EL2
	t.Log("Test EL2 registered block")
	check(testAddrCommon, el2NSBlocks[0], MemSpaceEL2)
	check(testAddrEL2, el2NSBlocks[1], MemSpaceEL2)
	check(testAddrEL2, el2NSBlocks[1], MemSpaceN)
	check(testAddrEL2, el2NSBlocks[1], MemSpaceAny)

	// Test EL1S
	t.Log("Test EL1S registered block")
	check(testAddrCommon, el01SBlocks[0], MemSpaceEL1S)
	check(testAddrEL1S, el01SBlocks[1], MemSpaceEL1S)
	check(testAddrEL1S, el01SBlocks[1], MemSpaceS)
	check(testAddrEL1S, el01SBlocks[1], MemSpaceAny)

	// Test EL2S
	t.Log("Test EL2S registered block")
	check(testAddrCommon, el2SBlocks[0], MemSpaceEL2S)
	check(testAddrEL2S, el2SBlocks[1], MemSpaceEL2S)
	check(testAddrEL2S, el2SBlocks[1], MemSpaceS)
	check(testAddrEL2S, el2SBlocks[1], MemSpaceAny)

	// Test EL3
	t.Log("Test EL3 registered block")
	check(testAddrCommon, el3Blocks[0], MemSpaceEL3)
	check(testAddrEL3, el3Blocks[1], MemSpaceEL3)
	check(testAddrEL3, el3Blocks[1], MemSpaceS)
	check(testAddrEL3, el3Blocks[1], MemSpaceAny)

	// Test EL1R
	t.Log("Test EL1R registered block")
	check(testAddrCommon, el01RBlocks[0], MemSpaceEL1R)
	check(testAddrEL1R, el01RBlocks[1], MemSpaceEL1R)
	check(testAddrEL1R, el01RBlocks[1], MemSpaceR)
	check(testAddrEL1R, el01RBlocks[1], MemSpaceAny)

	// Test EL2R
	t.Log("Test EL2R registered block")
	check(testAddrCommon, el2RBlocks[0], MemSpaceEL2R)
	check(testAddrEL2R, el2RBlocks[1], MemSpaceEL2R)
	check(testAddrEL2R, el2RBlocks[1], MemSpaceR)
	check(testAddrEL2R, el2RBlocks[1], MemSpaceAny)

	// Test ROOT
	t.Log("Test ROOT registered block")
	check(testAddrCommon, el3RootBlocks[0], MemSpaceRoot)
	check(testAddrEL3R, el3RootBlocks[1], MemSpaceRoot)
	check(testAddrEL3R, el3RootBlocks[1], MemSpaceAny)

	// Clear for next test
	mapper.RemoveAllAccessors()

	// General spaces tests (ANY, N, S, R)
	addAcc(testAddrCommon, el01NSBlocks[0], MemSpaceAny)
	addAcc(testAddrEL1N, el01NSBlocks[1], MemSpaceN)
	addAcc(testAddrEL2, el2NSBlocks[0], MemSpaceS)
	addAcc(testAddrEL3, el2NSBlocks[1], MemSpaceR)

	// ANY space should match all other spaces
	t.Log("Test ANY registered block")
	offset := uint64(0)
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceEL1N)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceEL2)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceEL1S)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceEL2S)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceEL3)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceEL1R)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceEL2R)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceS)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceN)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceR)
	offset += 4
	checkOffset(testAddrCommon, el01NSBlocks[0], offset, MemSpaceRoot)

	// Any N registered block
	t.Log("Test Any N registered block")
	offset = 0
	checkOffset(testAddrEL1N, el01NSBlocks[1], offset, MemSpaceEL1N)
	offset += 4
	checkOffset(testAddrEL1N, el01NSBlocks[1], offset, MemSpaceEL2)
	offset += 4
	checkOffset(testAddrEL1N, el01NSBlocks[1], offset, MemSpaceN)

	// Any S registered block
	t.Log("Test Any S registered block")
	offset = 0
	checkOffset(testAddrEL2, el2NSBlocks[0], offset, MemSpaceEL1S)
	offset += 4
	checkOffset(testAddrEL2, el2NSBlocks[0], offset, MemSpaceEL2S)
	offset += 4
	checkOffset(testAddrEL2, el2NSBlocks[0], offset, MemSpaceEL3)
	offset += 4
	checkOffset(testAddrEL2, el2NSBlocks[0], offset, MemSpaceS)

	// Any R registered block
	t.Log("Test Any R registered block")
	offset = 0
	checkOffset(testAddrEL3, el2NSBlocks[1], offset, MemSpaceEL1R)
	offset += 4
	checkOffset(testAddrEL3, el2NSBlocks[1], offset, MemSpaceEL2R)
	offset += 4
	checkOffset(testAddrEL3, el2NSBlocks[1], offset, MemSpaceR)
}
