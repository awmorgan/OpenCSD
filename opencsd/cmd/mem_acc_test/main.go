package main

import (
	"fmt"
	"os"

	"opencsd/common"
)

const (
	BLOCK_SIZE_BYTES = 4096
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

var testsPassed = 0
var testsFailed = 0

// Global test data blocks
var el01NSBlocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32
var el01SBlocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32
var el2NSBlocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32
var el2SBlocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32
var el3Blocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32
var el01RBlocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32
var el2RBlocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32
var el3RootBlocks [NUM_BLOCKS][BLOCK_NUM_WORDS]uint32

// Global mapper
var mapper *common.MemoryAccessorMapper

func blockValue(memSpace common.MemorySpace, blockNum int, index int) uint32 {
	return (uint32(memSpace) << 24) | (uint32(blockNum) << 16) | uint32(index)
}

func populateBlock(memSpace common.MemorySpace, block *[NUM_BLOCKS][BLOCK_NUM_WORDS]uint32) {
	for blockIdx := 0; blockIdx < NUM_BLOCKS; blockIdx++ {
		for wordIdx := 0; wordIdx < BLOCK_NUM_WORDS; wordIdx++ {
			block[blockIdx][wordIdx] = blockValue(memSpace, blockIdx, wordIdx)
		}
	}
}

func populateAllBlocks() {
	populateBlock(common.MemSpaceEL1N, &el01NSBlocks)
	populateBlock(common.MemSpaceEL2, &el2NSBlocks)
	populateBlock(common.MemSpaceEL1S, &el01SBlocks)
	populateBlock(common.MemSpaceEL2S, &el2SBlocks)
	populateBlock(common.MemSpaceEL3, &el3Blocks)
	populateBlock(common.MemSpaceEL1R, &el01RBlocks)
	populateBlock(common.MemSpaceEL2R, &el2RBlocks)
	populateBlock(common.MemSpaceROOT, &el3RootBlocks)
}

func logTestStart(testName string) {
	fmt.Printf("*** Test %s Starting.\n", testName)
}

func logTestEnd(testName string, passed int, failed int) {
	fmt.Printf("*** Test %s complete. (Pass: %d; Fail:%d)\n", testName, passed, failed)
}

func testOverlapRegions() {
	testName := "test_overlap_regions"
	logTestStart(testName)

	passed := 0
	failed := 0

	// Create test blocks as byte slices
	block1 := blockToBytes(el01NSBlocks[0][:])
	acc1 := common.NewMemoryBuffer(0x0000, block1)
	acc1.SetMemSpace(common.MemSpaceEL1N)

	err := mapper.AddAccessor(acc1, 0x0000, 0x0000+uint64(len(block1)), 0)
	if err != nil {
		fmt.Printf("Error: Failed to set memory accessor: %v\n", err)
		failed++
	} else {
		passed++
	}

	// Try to add overlapping accessor in same space - should fail
	block2 := blockToBytes(el01NSBlocks[1][:])
	acc2 := common.NewMemoryBuffer(0x1000, block2)
	acc2.SetMemSpace(common.MemSpaceEL1N)

	err = mapper.AddAccessor(acc2, 0x1000, 0x1000+uint64(len(block2)), 0)
	if err != nil {
		fmt.Printf("Error: expected successful add for non-overlapping range but got: %v\n", err)
		failed++
	} else {
		passed++
	}

	// Try to add overlapping accessor in same space - should fail
	acc3 := common.NewMemoryBuffer(0x1000, block2)
	acc3.SetMemSpace(common.MemSpaceEL1N)

	err = mapper.AddAccessor(acc3, 0x1000, 0x1000+uint64(len(block2)), 0)
	if err == nil {
		fmt.Printf("Error: expected OCSD_ERR_MEM_ACC_OVERLAP error for overlapping accessor range.\n")
		failed++
	} else {
		passed++
	}

	// Overlapping region - different memory space - should succeed
	block3 := blockToBytes(el01SBlocks[0][:])
	acc4 := common.NewMemoryBuffer(0x0000, block3)
	acc4.SetMemSpace(common.MemSpaceEL1S)

	err = mapper.AddAccessor(acc4, 0x0000, 0x0000+uint64(len(block3)), 0)
	if err != nil {
		fmt.Printf("Error: Failed to set overlapping memory accessor in other memory space: %v\n", err)
		failed++
	} else {
		passed++
	}

	// Overlapping region - more general memory space - should fail
	block4 := blockToBytes(el2SBlocks[0][:])
	acc5 := common.NewMemoryBuffer(0x0000, block4)
	acc5.SetMemSpace(common.MemSpaceS)

	err = mapper.AddAccessor(acc5, 0x0000, 0x0000+uint64(len(block4)), 0)
	if err == nil {
		fmt.Printf("Error: expected OCSD_ERR_MEM_ACC_OVERLAP error for overlapping general _S accessor range.\n")
		failed++
	} else {
		passed++
	}

	mapper.ClearAccessors()
	testsPassed += passed
	testsFailed += failed
	logTestEnd(testName, passed, failed)
}

func testMemSpaces() {
	testName := "test_mem_spaces"
	logTestStart(testName)

	passed := 0
	failed := 0

	// ========== PHASE 1: Test specific memory spaces ==========
	// Create accessors for all memory spaces
	accs := make([]*common.MemoryBuffer, 16)

	// Setup accessors for each space
	// Note: To avoid overlaps, second block of ROOT goes at a different address
	accs[0] = createAccessor(TEST_ADDR_COMMON, el01NSBlocks[0][:], common.MemSpaceEL1N)
	accs[1] = createAccessor(TEST_ADDR_EL1N, el01NSBlocks[1][:], common.MemSpaceEL1N)
	accs[2] = createAccessor(TEST_ADDR_COMMON, el2NSBlocks[0][:], common.MemSpaceEL2)
	accs[3] = createAccessor(TEST_ADDR_EL2, el2NSBlocks[1][:], common.MemSpaceEL2)
	accs[4] = createAccessor(TEST_ADDR_COMMON, el01SBlocks[0][:], common.MemSpaceEL1S)
	accs[5] = createAccessor(TEST_ADDR_EL1S, el01SBlocks[1][:], common.MemSpaceEL1S)
	accs[6] = createAccessor(TEST_ADDR_COMMON, el2SBlocks[0][:], common.MemSpaceEL2S)
	accs[7] = createAccessor(TEST_ADDR_EL2S, el2SBlocks[1][:], common.MemSpaceEL2S)
	accs[8] = createAccessor(TEST_ADDR_COMMON, el3Blocks[0][:], common.MemSpaceEL3)
	accs[9] = createAccessor(TEST_ADDR_EL3, el3Blocks[1][:], common.MemSpaceEL3)
	accs[10] = createAccessor(TEST_ADDR_COMMON, el01RBlocks[0][:], common.MemSpaceEL1R)
	accs[11] = createAccessor(TEST_ADDR_EL1R, el01RBlocks[1][:], common.MemSpaceEL1R)
	accs[12] = createAccessor(TEST_ADDR_COMMON, el2RBlocks[0][:], common.MemSpaceEL2R)
	accs[13] = createAccessor(TEST_ADDR_EL2R, el2RBlocks[1][:], common.MemSpaceEL2R)
	accs[14] = createAccessor(TEST_ADDR_EL3R, el3RootBlocks[0][:], common.MemSpaceROOT)
	accs[15] = createAccessor(TEST_ADDR_EL3R+BLOCK_SIZE_BYTES, el3RootBlocks[1][:], common.MemSpaceROOT)

	// Add all accessors to mapper
	for i, acc := range accs {
		startAddr := acc.BaseAddr
		endAddr := acc.EndAddr()
		err := mapper.AddAccessor(acc, startAddr, endAddr, 0)
		if err != nil {
			fmt.Printf("Error: Failed to set accessor %d: %v\n", i, err)
			failed++
		} else {
			passed++
		}
	}

	// Test individual spaces with their specific space
	fmt.Printf("Test EL1N registered block\n")
	if testReadSpecific(TEST_ADDR_COMMON, "EL1N", common.MemSpaceEL1N, blockValue(common.MemSpaceEL1N, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1N, "EL1N", common.MemSpaceEL1N, blockValue(common.MemSpaceEL1N, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1N, "EL1N", common.MemSpaceN, blockValue(common.MemSpaceEL1N, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1N, "EL1N", common.MemSpaceANY, blockValue(common.MemSpaceEL1N, 1, 0)) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("Test EL1N registered block\n")
	if testReadSpecific(TEST_ADDR_COMMON, "EL2N", common.MemSpaceEL2, blockValue(common.MemSpaceEL2, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2, "EL2N", common.MemSpaceEL2, blockValue(common.MemSpaceEL2, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2, "EL2N", common.MemSpaceN, blockValue(common.MemSpaceEL2, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2, "EL2N", common.MemSpaceANY, blockValue(common.MemSpaceEL2, 1, 0)) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("Test EL1S registered block\n")
	if testReadSpecific(TEST_ADDR_COMMON, "EL1S", common.MemSpaceEL1S, blockValue(common.MemSpaceEL1S, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1S, "EL1S", common.MemSpaceEL1S, blockValue(common.MemSpaceEL1S, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1S, "EL1S", common.MemSpaceS, blockValue(common.MemSpaceEL1S, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1S, "EL1S", common.MemSpaceANY, blockValue(common.MemSpaceEL1S, 1, 0)) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("Test EL2S registered block\n")
	if testReadSpecific(TEST_ADDR_COMMON, "EL2S", common.MemSpaceEL2S, blockValue(common.MemSpaceEL2S, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2S, "EL2S", common.MemSpaceEL2S, blockValue(common.MemSpaceEL2S, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2S, "EL2S", common.MemSpaceS, blockValue(common.MemSpaceEL2S, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2S, "EL2S", common.MemSpaceANY, blockValue(common.MemSpaceEL2S, 1, 0)) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("Test EL3 registered block\n")
	if testReadSpecific(TEST_ADDR_COMMON, "EL3", common.MemSpaceEL3, blockValue(common.MemSpaceEL3, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL3, "EL3", common.MemSpaceEL3, blockValue(common.MemSpaceEL3, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL3, "EL3", common.MemSpaceS, blockValue(common.MemSpaceEL3, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL3, "EL3", common.MemSpaceANY, blockValue(common.MemSpaceEL3, 1, 0)) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("Test EL1R registered block\n")
	if testReadSpecific(TEST_ADDR_COMMON, "EL1R", common.MemSpaceEL1R, blockValue(common.MemSpaceEL1R, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1R, "EL1R", common.MemSpaceEL1R, blockValue(common.MemSpaceEL1R, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1R, "EL1R", common.MemSpaceR, blockValue(common.MemSpaceEL1R, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL1R, "EL1R", common.MemSpaceANY, blockValue(common.MemSpaceEL1R, 1, 0)) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("Test EL2R registered block\n")
	if testReadSpecific(TEST_ADDR_COMMON, "EL2R", common.MemSpaceEL2R, blockValue(common.MemSpaceEL2R, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2R, "EL2R", common.MemSpaceEL2R, blockValue(common.MemSpaceEL2R, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2R, "EL2R", common.MemSpaceR, blockValue(common.MemSpaceEL2R, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL2R, "EL2R", common.MemSpaceANY, blockValue(common.MemSpaceEL2R, 1, 0)) {
		passed++
	} else {
		failed++
	}

	fmt.Printf("Test ROOT registered block\n")
	if testReadSpecific(TEST_ADDR_EL3R, "ROOT", common.MemSpaceROOT, blockValue(common.MemSpaceROOT, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL3R+BLOCK_SIZE_BYTES, "ROOT", common.MemSpaceROOT, blockValue(common.MemSpaceROOT, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadSpecific(TEST_ADDR_EL3R+BLOCK_SIZE_BYTES, "ROOT", common.MemSpaceANY, blockValue(common.MemSpaceROOT, 1, 0)) {
		passed++
	} else {
		failed++
	}

	// Clear mapper for phase 2
	mapper.ClearAccessors()

	// ========== PHASE 2: Test hierarchical spaces (ANY, N, S, R) ==========
	// Create new set of accessors with hierarchical spaces
	accs2 := make([]*common.MemoryBuffer, 4)

	accs2[0] = createAccessor(TEST_ADDR_COMMON, el01NSBlocks[0][:], common.MemSpaceANY)
	accs2[1] = createAccessor(TEST_ADDR_EL1N, el01NSBlocks[1][:], common.MemSpaceN)
	accs2[2] = createAccessor(TEST_ADDR_EL2, el2NSBlocks[0][:], common.MemSpaceS)
	accs2[3] = createAccessor(TEST_ADDR_EL3, el2NSBlocks[1][:], common.MemSpaceR)

	// Add all accessors to mapper for phase 2
	for i, acc := range accs2 {
		startAddr := acc.BaseAddr
		endAddr := acc.EndAddr()
		err := mapper.AddAccessor(acc, startAddr, endAddr, 0)
		if err != nil {
			fmt.Printf("Error: Failed to set accessor %d: %v\n", i, err)
			failed++
		} else {
			passed++
		}
	}

	// Test ANY space - should match all specific spaces
	fmt.Printf("Test ANY registered block\n")
	if testReadWithOffset(TEST_ADDR_COMMON, 0, "EL1N", common.MemSpaceEL1N, blockValue(common.MemSpaceEL1N, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 4, "EL2N", common.MemSpaceEL2, blockValue(common.MemSpaceEL1N, 0, 1)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 8, "EL1S", common.MemSpaceEL1S, blockValue(common.MemSpaceEL1N, 0, 2)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 12, "EL2S", common.MemSpaceEL2S, blockValue(common.MemSpaceEL1N, 0, 3)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 16, "EL3", common.MemSpaceEL3, blockValue(common.MemSpaceEL1N, 0, 4)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 20, "EL1R", common.MemSpaceEL1R, blockValue(common.MemSpaceEL1N, 0, 5)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 24, "EL2R", common.MemSpaceEL2R, blockValue(common.MemSpaceEL1N, 0, 6)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 28, "S", common.MemSpaceS, blockValue(common.MemSpaceEL1N, 0, 7)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 32, "N", common.MemSpaceN, blockValue(common.MemSpaceEL1N, 0, 8)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 36, "R", common.MemSpaceR, blockValue(common.MemSpaceEL1N, 0, 9)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_COMMON, 40, "ROOT", common.MemSpaceROOT, blockValue(common.MemSpaceEL1N, 0, 10)) {
		passed++
	} else {
		failed++
	}

	// Test N space - should match EL1N and EL2N
	fmt.Printf("Test Any N registered block\n")
	if testReadWithOffset(TEST_ADDR_EL1N, 0, "EL1N", common.MemSpaceEL1N, blockValue(common.MemSpaceEL1N, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_EL1N, 4, "EL2N", common.MemSpaceEL2, blockValue(common.MemSpaceEL1N, 1, 1)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_EL1N, 8, "N", common.MemSpaceN, blockValue(common.MemSpaceEL1N, 1, 2)) {
		passed++
	} else {
		failed++
	}

	// Test S space - should match EL1S, EL2S, EL3
	fmt.Printf("Test Any S registered block\n")
	if testReadWithOffset(TEST_ADDR_EL2, 0, "EL1S", common.MemSpaceEL1S, blockValue(common.MemSpaceEL2, 0, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_EL2, 4, "EL2S", common.MemSpaceEL2S, blockValue(common.MemSpaceEL2, 0, 1)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_EL2, 8, "EL3", common.MemSpaceEL3, blockValue(common.MemSpaceEL2, 0, 2)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_EL2, 12, "S", common.MemSpaceS, blockValue(common.MemSpaceEL2, 0, 3)) {
		passed++
	} else {
		failed++
	}

	// Test R space - should match EL1R, EL2R
	fmt.Printf("Test Any R registered block\n")
	if testReadWithOffset(TEST_ADDR_EL3, 0, "EL1R", common.MemSpaceEL1R, blockValue(common.MemSpaceEL2, 1, 0)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_EL3, 4, "EL2R", common.MemSpaceEL2R, blockValue(common.MemSpaceEL2, 1, 1)) {
		passed++
	} else {
		failed++
	}
	if testReadWithOffset(TEST_ADDR_EL3, 8, "R", common.MemSpaceR, blockValue(common.MemSpaceEL2, 1, 2)) {
		passed++
	} else {
		failed++
	}

	mapper.ClearAccessors()
	testsPassed += passed
	testsFailed += failed
	logTestEnd(testName, passed, failed)
}

func testTrcidCacheMemCb() {
	testName := "test_trcid_cache_mem_cb"
	logTestStart(testName)

	passed := 0
	failed := 0

	// Test callback accessor with trace ID
	callbackData := map[uint64][]byte{
		TEST_ADDR_COMMON: blockToBytes(el01NSBlocks[0][:]),
	}

	callback := func(addr uint64, traceID uint8, space common.MemorySpace, data []byte) int {
		if val, ok := callbackData[addr]; ok {
			if len(val) < len(data) {
				copy(data, val)
				return len(val)
			}
			copy(data, val[:len(data)])
			return len(data)
		}
		return 0
	}

	acc := common.NewCallbackAccessor(0x0000, 0x10000, callback)
	acc.SetMemSpace(common.MemSpaceANY)

	err := mapper.AddAccessor(acc, 0x0000, 0x10000, 0)
	if err != nil {
		fmt.Printf("Error: Failed to set callback memory accessor: %v\n", err)
		failed++
	} else {
		passed++
	}

	// Test read from callback
	data := make([]byte, 4)
	n, err := mapper.ReadMemory(TEST_ADDR_COMMON, 0, common.MemSpaceANY, data)
	if err != nil || n != 4 {
		fmt.Printf("Error: Failed to read from callback accessor: err=%v, n=%d\n", err, n)
		failed++
	} else {
		passed++
	}

	// Test with different trace ID
	n, err = mapper.ReadMemory(TEST_ADDR_COMMON, 1, common.MemSpaceANY, data)
	if err != nil || n != 4 {
		fmt.Printf("Error: Failed to read from callback accessor with different trace ID: err=%v, n=%d\n", err, n)
		failed++
	} else {
		passed++
	}

	// Test with different space
	n, err = mapper.ReadMemory(TEST_ADDR_COMMON, 0, common.MemSpaceEL1N, data)
	if err != nil || n != 4 {
		fmt.Printf("Error: Failed to read from callback accessor with specific space: err=%v, n=%d\n", err, n)
		failed++
	} else {
		passed++
	}

	mapper.ClearAccessors()
	testsPassed += passed
	testsFailed += failed
	logTestEnd(testName, passed, failed)
}

func createAccessor(addr uint64, blockData []uint32, space common.MemorySpace) *common.MemoryBuffer {
	data := blockToBytes(blockData)
	acc := common.NewMemoryBuffer(addr, data)
	acc.SetMemSpace(space)
	return acc
}

func blockToBytes(block []uint32) []byte {
	data := make([]byte, len(block)*4)
	for i, word := range block {
		data[i*4] = byte(word)
		data[i*4+1] = byte(word >> 8)
		data[i*4+2] = byte(word >> 16)
		data[i*4+3] = byte(word >> 24)
	}
	return data
}

func testReadAndCheck(addr uint64, expectedBlock []uint32, space common.MemorySpace) bool {
	data := make([]byte, 4)
	n, err := mapper.ReadMemory(addr, 0, space, data)
	if err != nil || n != 4 {
		fmt.Printf("Error reading address 0x%X in space %s: err=%v, n=%d\n", addr, space.String(), err, n)
		return false
	}

	// Verify first word matches
	expectedBytes := blockToBytes(expectedBlock[:1])
	if data[0] != expectedBytes[0] || data[1] != expectedBytes[1] ||
		data[2] != expectedBytes[2] || data[3] != expectedBytes[3] {
		fmt.Printf("Data mismatch at address 0x%X in space %s\n", addr, space.String())
		return false
	}

	fmt.Printf("  Read address 0x%X - %02X %02X %02X %02X\n", addr, data[0], data[1], data[2], data[3])
	return true
}

func testReadSpecific(addr uint64, spaceName string, space common.MemorySpace, expectedValue uint32) bool {
	data := make([]byte, 4)
	n, err := mapper.ReadMemory(addr, 0, space, data)
	if err != nil || n != 4 {
		fmt.Printf("Error: Read at address 0x%08X; %s\n", addr, spaceName)
		return false
	}

	// Verify value matches
	expected := make([]byte, 4)
	expected[0] = byte(expectedValue)
	expected[1] = byte(expectedValue >> 8)
	expected[2] = byte(expectedValue >> 16)
	expected[3] = byte(expectedValue >> 24)

	if data[0] != expected[0] || data[1] != expected[1] ||
		data[2] != expected[2] || data[3] != expected[3] {
		fmt.Printf("Read Test: Address 0x%08X; %s; [0x%08X]\n", addr, spaceName,
			uint32(data[0])|(uint32(data[1])<<8)|(uint32(data[2])<<16)|(uint32(data[3])<<24))
		return false
	}

	fmt.Printf("Read Test: Address 0x%08X; %s; [0x%08X]\n", addr, spaceName, expectedValue)
	return true
}

func testReadWithOffset(addr uint64, offset uint64, spaceName string, space common.MemorySpace, expectedValue uint32) bool {
	data := make([]byte, 4)
	n, err := mapper.ReadMemory(addr+offset, 0, space, data)
	if err != nil || n != 4 {
		fmt.Printf("Error: Read at address 0x%08X; %s\n", addr+offset, spaceName)
		return false
	}

	// Verify value matches
	expected := make([]byte, 4)
	expected[0] = byte(expectedValue)
	expected[1] = byte(expectedValue >> 8)
	expected[2] = byte(expectedValue >> 16)
	expected[3] = byte(expectedValue >> 24)

	if data[0] != expected[0] || data[1] != expected[1] ||
		data[2] != expected[2] || data[3] != expected[3] {
		fmt.Printf("Read Test: Address 0x%08X; %s; [0x%08X]\n", addr+offset, spaceName,
			uint32(data[0])|(uint32(data[1])<<8)|(uint32(data[2])<<16)|(uint32(data[3])<<24))
		return false
	}

	fmt.Printf("Read Test: Address 0x%08X; %s; [0x%08X]\n", addr+offset, spaceName, expectedValue)
	return true
}

func main() {
	fmt.Println("OpenCSD memory access tests.")
	fmt.Println("----------------------------\n")
	fmt.Printf("Library Version : Go port\n\n")

	// Initialize mapper
	mapper = common.NewMemoryAccessorMapper()

	// Populate test data
	populateAllBlocks()

	// Run tests
	testOverlapRegions()
	testTrcidCacheMemCb()
	testMemSpaces()

	fmt.Printf("\n*** Memory access tests complete.***\n")
	fmt.Printf("Passed: %d; Failed: %d\n", testsPassed, testsFailed)

	if testsFailed != 0 {
		os.Exit(-2)
	}
}
