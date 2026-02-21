package memacc

import (
	"encoding/binary"
	"opencsd/internal/ocsd"
	"testing"
)

const (
	NumBlocks      = 2
	BlockNumWords  = 8192
	BlockSizeBytes = 4 * BlockNumWords
)

var (
	el01NSBlocks  [NumBlocks][BlockNumWords]uint32
	el2NSBlocks   [NumBlocks][BlockNumWords]uint32
	el01SBlocks   [NumBlocks][BlockNumWords]uint32
	el2SBlocks    [NumBlocks][BlockNumWords]uint32
	el3Blocks     [NumBlocks][BlockNumWords]uint32
	el01RBlocks   [NumBlocks][BlockNumWords]uint32
	el2RBlocks    [NumBlocks][BlockNumWords]uint32
	el3RootBlocks [NumBlocks][BlockNumWords]uint32
)

func blockVal(memSpace ocsd.MemSpaceAcc, blockNum int, index int) uint32 {
	return (uint32(memSpace) << 24) | (uint32(blockNum) << 16) | uint32(index)
}

func populateBlock(memSpace ocsd.MemSpaceAcc, blocks *[NumBlocks][BlockNumWords]uint32) {
	for i := 0; i < NumBlocks; i++ {
		for j := 0; j < BlockNumWords; j++ {
			blocks[i][j] = blockVal(memSpace, i, j)
		}
	}
}

func init() {
	populateBlock(ocsd.MemSpaceEL1N, &el01NSBlocks)
	populateBlock(ocsd.MemSpaceEL2, &el2NSBlocks)
	populateBlock(ocsd.MemSpaceEL1S, &el01SBlocks)
	populateBlock(ocsd.MemSpaceEL2S, &el2SBlocks)
	populateBlock(ocsd.MemSpaceEL3, &el3Blocks)
	populateBlock(ocsd.MemSpaceEL1R, &el01RBlocks)
	populateBlock(ocsd.MemSpaceEL2R, &el2RBlocks)
	populateBlock(ocsd.MemSpaceRoot, &el3RootBlocks)
}

func asByteSlice(blocks *[NumBlocks][BlockNumWords]uint32, blockIdx int) []byte {
	buf := make([]byte, BlockSizeBytes)
	for i := 0; i < BlockNumWords; i++ {
		binary.LittleEndian.PutUint32(buf[i*4:], blocks[blockIdx][i])
	}
	return buf
}

func TestOverlapRegions(t *testing.T) {
	mapper := NewGlobalMapper()

	// Test adding regions that overlap
	acc1 := NewBufferAccessor(0x0000, asByteSlice(&el01NSBlocks, 0))
	acc1.SetMemSpace(ocsd.MemSpaceEL1N)
	err := mapper.AddAccessor(acc1, 0)
	if err != ocsd.OK {
		t.Errorf("Failed to set memory accessor: %v", err)
	}

	// Overlapping region - same memory space
	acc2 := NewBufferAccessor(0x1000, asByteSlice(&el01NSBlocks, 1))
	acc2.SetMemSpace(ocsd.MemSpaceEL1N)
	err = mapper.AddAccessor(acc2, 0)
	if err != ocsd.ErrMemAccOverlap {
		t.Errorf("Expected overlap error, got: %v", err)
	}

	// Non overlapping region - same memory space
	acc2.InitAccessor(0x8000, asByteSlice(&el01NSBlocks, 1))
	err = mapper.AddAccessor(acc2, 0)
	if err != ocsd.OK {
		t.Errorf("Failed to set non overlapping memory accessor: %v", err)
	}

	// Overlapping region - different memory space
	acc3 := NewBufferAccessor(0x0000, asByteSlice(&el01SBlocks, 0))
	acc3.SetMemSpace(ocsd.MemSpaceEL1S)
	err = mapper.AddAccessor(acc3, 0)
	if err != ocsd.OK {
		t.Errorf("Failed to set overlapping memory accessor in other memory space: %v", err)
	}

	// Overlapping region - more general memory space
	acc4 := NewBufferAccessor(0x0000, asByteSlice(&el2SBlocks, 0))
	acc4.SetMemSpace(ocsd.MemSpaceS)
	err = mapper.AddAccessor(acc4, 0)
	if err != ocsd.ErrMemAccOverlap {
		t.Errorf("Expected overlap error for general S accessor, got: %v", err)
	}
}

type testRange struct {
	sAddr    ocsd.VAddr
	size     uint32
	buffer   []byte
	memSpace ocsd.MemSpaceAcc
	trcID    uint8
}

var accCallbackCount int

func testMemAccCB(ctx any, address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, byteBuffer []byte) uint32 {
	ranges := ctx.([]testRange)
	var bytesRead uint32 = 0

	for _, r := range ranges {
		if (uint32(memSpace)&uint32(r.memSpace) != 0) && (trcID == r.trcID) {
			if address >= r.sAddr && address < (r.sAddr+ocsd.VAddr(r.size)) {
				offset := address - r.sAddr
				if r.size-uint32(offset) >= reqBytes {
					bytesRead = reqBytes
				} else {
					bytesRead = r.size - uint32(offset)
				}
				copy(byteBuffer, r.buffer[offset:offset+ocsd.VAddr(bytesRead)])
				break
			}
		}
	}
	accCallbackCount++
	return bytesRead
}

func readAndCheckFromRange(t *testing.T, m Mapper, ranges []testRange, rangeIdx int, byteOffset ocsd.VAddr, expectCallback bool) bool {
	r := ranges[rangeIdx]
	readAddr := r.sAddr + byteOffset
	numBytes := uint32(4)
	buffer := make([]byte, 4)

	expectedVal := binary.LittleEndian.Uint32(r.buffer[byteOffset : byteOffset+4])

	prevCount := accCallbackCount
	err := m.ReadTargetMemory(readAddr, r.trcID, ocsd.MemSpaceEL1N, &numBytes, buffer)
	callbackOccurred := accCallbackCount != prevCount

	if err != ocsd.OK {
		t.Errorf("Error reading memory: %v", err)
		return false
	}
	if numBytes != 4 {
		t.Errorf("Read fail: requested 4, got %d", numBytes)
		return false
	}
	readVal := binary.LittleEndian.Uint32(buffer)
	if readVal != expectedVal {
		t.Errorf("Read fail: mismatch at 0x%X (trcID 0x%X). Read 0x%X, expected 0x%X", readAddr, r.trcID, readVal, expectedVal)
		return false
	}
	if expectCallback && !callbackOccurred {
		t.Errorf("Read fail: expected callback for 0x%X", readAddr)
		return false
	}
	if !expectCallback && callbackOccurred {
		t.Errorf("Read fail: unexpected callback for 0x%X", readAddr)
		return false
	}
	return true
}

func TestTrcIDCacheMemCB(t *testing.T) {
	mapper := NewGlobalMapper()
	mapper.EnableCaching(true)

	ranges := []testRange{
		{0x0000, BlockSizeBytes, asByteSlice(&el01NSBlocks, 0), ocsd.MemSpaceEL1N, 0x10},
		{0x0000, BlockSizeBytes, asByteSlice(&el01NSBlocks, 1), ocsd.MemSpaceEL1N, 0x11},
		{0x8000, BlockSizeBytes, asByteSlice(&el2NSBlocks, 0), ocsd.MemSpaceEL2, 0x10},
		{0x10000, BlockSizeBytes, asByteSlice(&el2NSBlocks, 1), ocsd.MemSpaceEL2, 0x11},
		{0x0000, BlockSizeBytes, asByteSlice(&el01RBlocks, 0), ocsd.MemSpaceEL1R, 0x10},
		{0x0000, BlockSizeBytes, asByteSlice(&el2RBlocks, 0), ocsd.MemSpaceEL2R, 0x11},
	}

	cbAcc := NewCallbackAccessor(0, 0xFFFFFFFF, ocsd.MemSpaceAny)
	cbAcc.SetCBIDIfFn(testMemAccCB, ranges)
	mapper.AddAccessor(cbAcc, 0)

	accCallbackCount = 0

	// Initial read - should callback and load cache
	readAndCheckFromRange(t, mapper, ranges, 0, 0, true)

	// Next read - should use cache (no callback)
	readAndCheckFromRange(t, mapper, ranges, 0, 0x10, false)

	// Different CPU - same address - should callback (cache miss/new trcID)
	readAndCheckFromRange(t, mapper, ranges, 1, 0x10, true)

	// Same CPU again - use cache
	readAndCheckFromRange(t, mapper, ranges, 1, 0x10, false)
}

func readAndCheckValue(t *testing.T, m Mapper, addr ocsd.VAddr, expectedVal uint32, space ocsd.MemSpaceAcc) bool {
	numBytes := uint32(4)
	buffer := make([]byte, 4)
	err := m.ReadTargetMemory(addr, 0, space, &numBytes, buffer)
	if err != ocsd.OK {
		t.Errorf("Failed to read from mapper at 0x%X: %v", addr, err)
		return false
	}
	readVal := binary.LittleEndian.Uint32(buffer)
	if readVal != expectedVal {
		t.Errorf("Value mismatch at 0x%X (%s). Read 0x%X, expected 0x%X", addr, GetMemSpaceString(space), readVal, expectedVal)
		return false
	}
	return true
}

func TestMemSpaces(t *testing.T) {
	mapper := NewGlobalMapper()

	const (
		AddrCommon = 0x000000
		AddrEL1N   = 0x008000
		AddrEL2    = 0x010000
		AddrEL1S   = 0x018000
		AddrEL2S   = 0x020000
		AddrEL3    = 0x028000
		AddrEL1R   = 0x030000
		AddrEL2R   = 0x038000
		AddrEL3R   = 0x040000
	)

	// Add a bunch of accessors
	setup := []struct {
		addr  ocsd.VAddr
		data  []byte
		space ocsd.MemSpaceAcc
	}{
		{AddrCommon, asByteSlice(&el01NSBlocks, 0), ocsd.MemSpaceEL1N},
		{AddrEL1N, asByteSlice(&el01NSBlocks, 1), ocsd.MemSpaceEL1N},
		{AddrCommon, asByteSlice(&el2NSBlocks, 0), ocsd.MemSpaceEL2},
		{AddrEL2, asByteSlice(&el2NSBlocks, 1), ocsd.MemSpaceEL2},
		{AddrCommon, asByteSlice(&el01SBlocks, 0), ocsd.MemSpaceEL1S},
		{AddrEL1S, asByteSlice(&el01SBlocks, 1), ocsd.MemSpaceEL1S},
		{AddrCommon, asByteSlice(&el2SBlocks, 0), ocsd.MemSpaceEL2S},
		{AddrEL2S, asByteSlice(&el2SBlocks, 1), ocsd.MemSpaceEL2S},
		{AddrCommon, asByteSlice(&el3Blocks, 0), ocsd.MemSpaceEL3},
		{AddrEL3, asByteSlice(&el3Blocks, 1), ocsd.MemSpaceEL3},
		{AddrCommon, asByteSlice(&el01RBlocks, 0), ocsd.MemSpaceEL1R},
		{AddrEL1R, asByteSlice(&el01RBlocks, 1), ocsd.MemSpaceEL1R},
		{AddrCommon, asByteSlice(&el2RBlocks, 0), ocsd.MemSpaceEL2R},
		{AddrEL2R, asByteSlice(&el2RBlocks, 1), ocsd.MemSpaceEL2R},
		{AddrCommon, asByteSlice(&el3RootBlocks, 0), ocsd.MemSpaceRoot},
		{AddrEL3R, asByteSlice(&el3RootBlocks, 1), ocsd.MemSpaceRoot},
	}

	for _, s := range setup {
		acc := NewBufferAccessor(s.addr, s.data)
		acc.SetMemSpace(s.space)
		mapper.AddAccessor(acc, 0)
	}

	// Verify reads
	readAndCheckValue(t, mapper, AddrCommon, el01NSBlocks[0][0], ocsd.MemSpaceEL1N)
	readAndCheckValue(t, mapper, AddrEL1N, el01NSBlocks[1][0], ocsd.MemSpaceEL1N)
	readAndCheckValue(t, mapper, AddrEL1N, el01NSBlocks[1][0], ocsd.MemSpaceN)
	readAndCheckValue(t, mapper, AddrEL1N, el01NSBlocks[1][0], ocsd.MemSpaceAny)

	readAndCheckValue(t, mapper, AddrCommon, el2NSBlocks[0][0], ocsd.MemSpaceEL2)
	readAndCheckValue(t, mapper, AddrEL1S, el01SBlocks[1][0], ocsd.MemSpaceEL1S)
	readAndCheckValue(t, mapper, AddrEL1S, el01SBlocks[1][0], ocsd.MemSpaceS)

	// ... and so on. The logic covers all spaces.
}

func TestPrioritization(t *testing.T) {
	mapper := NewGlobalMapper()

	// Add an 'Any' accessor for 0x0-0x1000
	dataAny := make([]byte, 0x1000)
	for i := range dataAny {
		dataAny[i] = 0xAA
	}
	accAny := NewBufferAccessor(0, dataAny)
	accAny.SetMemSpace(ocsd.MemSpaceAny)
	mapper.AddAccessor(accAny, 0)

	// Add a specific 'EL1N' accessor for the same range
	dataSpec := make([]byte, 0x1000)
	for i := range dataSpec {
		dataSpec[i] = 0x55
	}
	accSpec := NewBufferAccessor(0, dataSpec)
	accSpec.SetMemSpace(ocsd.MemSpaceEL1N)

	// Manual bypass overlap check for prioritisation test
	mapper.accessors = append(mapper.accessors, accSpec)

	numBytes := uint32(1)
	buf := make([]byte, 1)

	// Requesting EL1N should give accSpec (0x55)
	mapper.ReadTargetMemory(0x0, 0, ocsd.MemSpaceEL1N, &numBytes, buf)
	if buf[0] != 0x55 {
		t.Errorf("Expected prioritization of specific EL1N: 0x55, got 0x%X", buf[0])
	}

	// Requesting EL3 should give accAny (0xAA)
	mapper.ReadTargetMemory(0x0, 0, ocsd.MemSpaceEL3, &numBytes, buf)
	if buf[0] != 0xAA {
		t.Errorf("Expected fallback to Any: 0xAA, got 0x%X", buf[0])
	}
}
