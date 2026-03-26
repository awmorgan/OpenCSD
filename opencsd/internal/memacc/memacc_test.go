package memacc

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	for i := range NumBlocks {
		for j := range BlockNumWords {
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
	for i := range BlockNumWords {
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
	if err != nil {
		t.Errorf("Failed to set memory accessor: %v", err)
	}

	// Overlapping region - same memory space
	acc2 := NewBufferAccessor(0x1000, asByteSlice(&el01NSBlocks, 1))
	acc2.SetMemSpace(ocsd.MemSpaceEL1N)
	err = mapper.AddAccessor(acc2, 0)
	if !errors.Is(err, ocsd.ErrMemAccOverlap) {
		t.Errorf("Expected overlap error, got: %v", err)
	}

	// Non overlapping region - same memory space
	acc2.Configure(0x8000, asByteSlice(&el01NSBlocks, 1))
	err = mapper.AddAccessor(acc2, 0)
	if err != nil {
		t.Errorf("Failed to set non overlapping memory accessor: %v", err)
	}

	// Overlapping region - different memory space
	acc3 := NewBufferAccessor(0x0000, asByteSlice(&el01SBlocks, 0))
	acc3.SetMemSpace(ocsd.MemSpaceEL1S)
	err = mapper.AddAccessor(acc3, 0)
	if err != nil {
		t.Errorf("Failed to set overlapping memory accessor in other memory space: %v", err)
	}

	// Overlapping region - more general memory space
	acc4 := NewBufferAccessor(0x0000, asByteSlice(&el2SBlocks, 0))
	acc4.SetMemSpace(ocsd.MemSpaceS)
	err = mapper.AddAccessor(acc4, 0)
	if !errors.Is(err, ocsd.ErrMemAccOverlap) {
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

func makeTestMemAccCB(ranges []testRange) ocsd.MemAccessorWithID {

	return func(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32 {
		var bytesRead uint32 = 0

		for _, r := range ranges {
			if (uint32(memSpace)&uint32(r.memSpace) != 0) && (trcID == r.trcID) {
				if address >= r.sAddr && address < (r.sAddr+ocsd.VAddr(r.size)) {
					offset := address - r.sAddr
					bytesRead = min(r.size-uint32(offset), reqBytes)
					copy(buffer, r.buffer[offset:offset+ocsd.VAddr(bytesRead)])
					break
				}
			}
		}
		accCallbackCount++
		return bytesRead
	}
}

func readAndCheckFromRange(t *testing.T, m Mapper, ranges []testRange, rangeIdx int, byteOffset ocsd.VAddr, expectCallback bool) bool {
	r := ranges[rangeIdx]
	readAddr := r.sAddr + byteOffset
	numBytes := uint32(4)
	buffer := make([]byte, 4)

	expectedVal := binary.LittleEndian.Uint32(r.buffer[byteOffset : byteOffset+4])

	prevCount := accCallbackCount
	numBytes, err := m.Read(readAddr, r.trcID, ocsd.MemSpaceEL1N, numBytes, buffer)
	callbackOccurred := accCallbackCount != prevCount

	if err != nil {
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
	cbAcc.SetTraceIDCallback(makeTestMemAccCB(ranges))
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
	_, err := m.Read(addr, 0, space, numBytes, buffer)
	if err != nil {
		t.Errorf("Failed to read from mapper at 0x%X: %v", addr, err)
		return false
	}
	readVal := binary.LittleEndian.Uint32(buffer)
	if readVal != expectedVal {
		t.Errorf("Value mismatch at 0x%X (%s). Read 0x%X, expected 0x%X", addr, MemSpaceString(space), readVal, expectedVal)
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
	numBytes, _ = mapper.Read(0x0, 0, ocsd.MemSpaceEL1N, numBytes, buf)
	if buf[0] != 0x55 {
		t.Errorf("Expected prioritization of specific EL1N: 0x55, got 0x%X", buf[0])
	}

	// Requesting EL3 should give accAny (0xAA)
	_, _ = mapper.Read(0x0, 0, ocsd.MemSpaceEL3, numBytes, buf)
	if buf[0] != 0xAA {
		t.Errorf("Expected fallback to Any: 0xAA, got 0x%X", buf[0])
	}
}

func TestAccessorRemoval(t *testing.T) {
	mapper := NewGlobalMapper()
	acc1 := NewBufferAccessor(0x1000, make([]byte, 100))
	acc2 := NewBufferAccessor(0x2000, make([]byte, 100))

	mapper.AddAccessor(acc1, 0)
	mapper.AddAccessor(acc2, 0)

	if len(mapper.accessors) != 2 {
		t.Errorf("Expected 2 accessors, got %d", len(mapper.accessors))
	}

	err := mapper.RemoveAccessor(acc1)
	if err != nil {
		t.Errorf("Expected OK, got %v", err)
	}
	if len(mapper.accessors) != 1 {
		t.Errorf("Expected 1 accessor, got %d", len(mapper.accessors))
	}

	// Remove non-existent
	accFake := NewBufferAccessor(0x3000, make([]byte, 100))
	err = mapper.RemoveAccessor(accFake)
	if !errors.Is(err, ocsd.ErrInvalidParamVal) {
		t.Errorf("Expected ErrInvalidParamVal, got %v", err)
	}

	mapper.RemoveAllAccessors()
	if len(mapper.accessors) != 0 {
		t.Errorf("Expected 0 accessors after RemoveAllAccessors")
	}
}

func TestCacheInvalidation(t *testing.T) {
	mapper := NewGlobalMapper()
	mapper.EnableCaching(true)

	acc := NewBufferAccessor(0, []byte{1, 2, 3, 4})
	mapper.AddAccessor(acc, 0)

	buf := make([]byte, 4)

	// Populate cache for TrcID 0x10
	_, _ = mapper.Read(0, 0x10, ocsd.MemSpaceAny, 4, buf)
	if mapper.cache.blocks[mapper.cache.mruIdx].ValidLen == 0 || mapper.cache.blocks[mapper.cache.mruIdx].TrcID != 0x10 {
		t.Errorf("Cache not populated for 0x10")
	}

	// Populate cache for TrcID 0x20
	acc2 := NewBufferAccessor(0x1000, []byte{5, 6, 7, 8})
	mapper.AddAccessor(acc2, 0)
	_, _ = mapper.Read(0x1000, 0x20, ocsd.MemSpaceAny, 4, buf)

	// Invalidate by Trace ID
	mapper.InvalidateMemAccCache(0x10)
	for _, block := range mapper.cache.blocks {
		if block.TrcID == 0x10 && block.ValidLen > 0 {
			t.Errorf("Cache for 0x10 not invalidated")
		}
	}

	// Invalidate All
	mapper.cache.InvalidateAll()
	for _, block := range mapper.cache.blocks {
		if block.ValidLen > 0 {
			t.Errorf("Cache not fully invalidated")
		}
	}

	// Test InvalidateAll when cache is disabled
	mapper.EnableCaching(false)
	mapper.cache.InvalidateAll()
	mapper.cache.InvalidateByTraceID(0x20)
}

func TestEdgeCasesAndUtilities(t *testing.T) {
	// SetCacheSizes
	mapper := NewGlobalMapper()
	mapper.EnableCaching(true)

	err := mapper.cache.SetCacheSizes(10, 1, true)
	if !errors.Is(err, ocsd.ErrInvalidParamVal) {
		t.Errorf("Expected ErrInvalidParamVal for SetCacheSizes limits, got: %v", err)
	}
	err = mapper.cache.SetCacheSizes(10, 1, false)
	if err != nil {
		t.Errorf("Expected nil for SetCacheSizes auto-limit")
	}
	if mapper.cache.pageSize != MinPageSize || mapper.cache.numPages != MinPages {
		t.Errorf("Cache sizes not clamped to min")
	}

	mapper.cache.SetCacheSizes(MaxPageSize+1000, MaxPages+10, false)
	if mapper.cache.pageSize != MaxPageSize || mapper.cache.numPages != MaxPages {
		t.Errorf("Cache sizes not clamped to max")
	}

	// ValidateRange & Range limits
	acc1 := NewBufferAccessor(0x1000, make([]byte, 10))
	acc1.StartAddress = 0x2000
	acc1.EndAddress = 0x1000
	if acc1.ValidateRange() {
		t.Errorf("ValidateRange should fail for start >= end")
	}

	acc1.StartAddress = 0x1001
	acc1.EndAddress = 0x1005
	if acc1.ValidateRange() {
		t.Errorf("ValidateRange should fail for unaligned start")
	}

	acc1.StartAddress = 0x1000
	acc1.EndAddress = 0x1004
	if acc1.ValidateRange() {
		t.Errorf("ValidateRange should fail for unaligned end")
	}

	// Range Getters
	acc2 := NewBufferAccessor(0x1000, make([]byte, 100))
	st, en := acc2.Range()
	if st != 0x1000 || en != 0x1000+100-1 {
		t.Errorf("Range incorrect")
	}

	if acc2.Type() != TypeBufPtr {
		t.Errorf("Type incorrect")
	}
	if acc2.AddrStartOfRange(0x1001) {
		t.Errorf("AddrStartOfRange false positive")
	}
	if !acc2.AddrStartOfRange(0x1000) {
		t.Errorf("AddrStartOfRange false negative")
	}

	// MemSpaceString & String
	if MemSpaceString(ocsd.MemSpaceEL1N) != "EL1N" {
		t.Errorf("MemSpaceString mismatch")
	}
	if MemSpaceString(ocsd.MemSpaceEL2) != "EL2N" {
		t.Errorf("MemSpaceString mismatch for EL2")
	}
	if MemSpaceString(ocsd.MemSpaceN) != "Any NS" {
		t.Errorf("MemSpaceString mismatch for non-secure aggregate")
	}
	if MemSpaceString(ocsd.MemSpaceNone) != "None" {
		t.Errorf("MemSpaceString mismatch")
	}
	str := acc2.String()
	if str == "" {
		t.Errorf("String() returned empty")
	}

	// Test other MemSpaceString values
	spaces := []ocsd.MemSpaceAcc{
		ocsd.MemSpaceEL1S, ocsd.MemSpaceEL2, ocsd.MemSpaceEL3, ocsd.MemSpaceEL2S,
		ocsd.MemSpaceEL1R, ocsd.MemSpaceEL2R, ocsd.MemSpaceRoot, ocsd.MemSpaceS,
		ocsd.MemSpaceN, ocsd.MemSpaceR, ocsd.MemSpaceAny, ocsd.MemSpaceAcc(0xABC),
	}
	for _, s := range spaces {
		MemSpaceString(s)
	}

	// Test base accessor unknown type inside String()
	acc2.AccType = TypeUnknown
	if acc2.String() == "" {
		t.Errorf("String() error")
	}
	acc2.AccType = TypeCBIf
	if acc2.String() == "" {
		t.Errorf("String() error")
	}
	acc2.AccType = TypeFile
	if acc2.String() == "" {
		t.Errorf("String() error")
	}

	acc2.AccType = TypeBufPtr // restore
	acc2.SetMemSpace(ocsd.MemSpaceEL1N)
	if acc2.MemSpace() != ocsd.MemSpaceEL1N {
		t.Errorf("MemSpace error")
	}
}

func testMemAccSimpleCB(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, reqBytes uint32, buffer []byte) uint32 {
	if address == 0 {
		buf := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		read := min(reqBytes, uint32(len(buf)))
		copy(buffer, buf[:read])
		return read
	}
	return 0
}

func TestAlternativeCallback(t *testing.T) {
	cbAcc := NewCallbackAccessor(0, 0xFFFFFFFF, ocsd.MemSpaceAny)
	cbAcc.SetCallback(testMemAccSimpleCB)

	readBuf := make([]byte, 4)
	read := cbAcc.ReadBytes(0, ocsd.MemSpaceEL1N, 0, 4, readBuf)
	if read != 4 {
		t.Errorf("Alternative callback read fail")
	}
	if readBuf[0] != 0xDE {
		t.Errorf("Alternative callback data fail")
	}

	// test when not in range or space
	if cbAcc.ReadBytes(0, ocsd.MemSpaceNone, 0, 4, readBuf) != 4 {
		t.Errorf("Callback accessor should delegate without local memspace filtering")
	}

	// test Configure
	cbAcc.Configure(0x100, 0x200, ocsd.MemSpaceEL1N)
	st, en := cbAcc.Range()
	if st != 0x100 || en != 0x200 {
		t.Errorf("Configure mismatch")
	}
}

func TestGlobalMapperRead(t *testing.T) {
	mapper := NewGlobalMapper()
	data := []byte{0x11, 0x22, 0x33, 0x44}
	acc := NewBufferAccessor(0x1000, data)
	if err := mapper.AddAccessor(acc, 0); err != nil {
		t.Fatalf("failed to add accessor: %v", err)
	}

	buf := make([]byte, 4)
	read, err := mapper.Read(0x1000, 0, ocsd.MemSpaceAny, 4, buf)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if read != 4 {
		t.Fatalf("expected read size 4, got %d", read)
	}
	if binary.LittleEndian.Uint32(buf) != 0x44332211 {
		t.Fatalf("unexpected read data: %x", buf)
	}

	buf = make([]byte, 2)
	read, err = mapper.Read(0x1000, 0, ocsd.MemSpaceAny, 4, buf)
	if err != nil {
		t.Fatalf("unexpected short-buffer read error: %v", err)
	}
	if read != 2 {
		t.Fatalf("expected read size 2 with short buffer, got %d", read)
	}
}

func testMemAccBadLenCB(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, reqBytes uint32, buffer []byte) uint32 {
	fmt.Printf("testMemAccBadLenCB called! reqBytes=%d\n", reqBytes)
	return reqBytes + 1 // deliberately bad
}

func TestMapper_ErrorAndCacheEdgePaths(t *testing.T) {
	// 1. Cache invalidations with nil blocks
	mapper := NewGlobalMapper()
	mapper.cache.InvalidateAll()
	mapper.cache.InvalidateByTraceID(0x10)

	// 2. BytesInRange where avail <= reqBytes
	accBuf := NewBufferAccessor(0, []byte{1, 2, 3, 4})
	avail := accBuf.BytesInRange(0, 10)
	if avail != 4 {
		t.Errorf("Expected 4 avail bytes")
	}

	// 3. RemoveAccessor hitting m.accCurr
	mapper.EnableCaching(true)
	mapper.AddAccessor(accBuf, 0)
	mapper.accCurr = accBuf // manually set
	mapper.RemoveAccessor(accBuf)
	if mapper.accCurr != nil {
		t.Errorf("accCurr should be nil")
	}

	// 4. RemoveAccessor and RemoveAllAccessors with cache disabled
	mapper.EnableCaching(false)
	mapper.AddAccessor(accBuf, 0)
	mapper.RemoveAccessor(accBuf)

	// Add invalid accessor
	accBuf.EndAddress = 0 // invalid range
	err := mapper.AddAccessor(accBuf, 0)
	if !errors.Is(err, ocsd.ErrMemAccRangeInvalid) {
		t.Errorf("Expected invalid range error")
	}

	mapper.RemoveAllAccessors()

	// 5. Buffer ReadBytes out of bounds / memspace
	accBuf.Configure(0, []byte{1, 2, 3, 4})
	accBuf.SetMemSpace(ocsd.MemSpaceEL1N)
	readBuf := make([]byte, 4)
	if accBuf.ReadBytes(0x10, ocsd.MemSpaceEL1N, 0, 4, readBuf) != 0 {
		t.Errorf("Should not read")
	}
	if accBuf.ReadBytes(0, ocsd.MemSpaceEL2, 0, 4, readBuf) != 4 {
		t.Errorf("Buffer accessor should ignore memspace filtering")
	}

	// 6. Test ReadTargetMemory over-read error
	mapper = NewGlobalMapper()
	mapper.EnableCaching(false) // hit the cache.Enabled() == false branch after findAccessor
	badAcc := NewCallbackAccessor(0, 0xFF, ocsd.MemSpaceAny)
	badAcc.SetCallback(testMemAccBadLenCB)
	mapper.AddAccessor(badAcc, 0)

	numBytes := uint32(4)
	err = mapper.ReadTargetMemory(0, 0, ocsd.MemSpaceAny, &numBytes, readBuf)
	if !errors.Is(err, ocsd.ErrMemAccBadLen) {
		t.Errorf("Expected ErrMemAccBadLen, got %v", err)
	}

	// 7. Hit ReadBytesFromCache cache miss / edge cases
	mapper.EnableCaching(true)
	mapper.accCurr = accBuf // set back to valid buffer
	numBytes = 4
	numBytes, err2 := mapper.cache.Read(accBuf, 0x1000, ocsd.MemSpaceEL1N, 0x10, numBytes, readBuf) // out of bounds
	if err2 != nil {
		t.Errorf("Expected OK on cache miss/out-of-range read, got %v", err2)
	}
	if numBytes != 0 {
		t.Errorf("Expected 0 bytes for cache miss/out-of-range read, got %d", numBytes)
	}
}

func TestCacheReadBytesFromCache_ClampsPageBaseToAccessorStart(t *testing.T) {
	accBuf := NewBufferAccessor(0x1004, []byte{0x11, 0x22, 0x33, 0x44, 0x55})
	accBuf.SetMemSpace(ocsd.MemSpaceEL1N)

	cache := NewCache()
	cache.EnableCaching(true)

	numBytes := uint32(4)
	readBuf := make([]byte, 4)
	numBytes, err := cache.Read(accBuf, 0x1004, ocsd.MemSpaceEL1N, 0x10, numBytes, readBuf)
	if err != nil {
		t.Fatalf("Expected cache read OK for non-page-aligned accessor start, got %v", err)
	}
	if numBytes != 4 {
		t.Fatalf("Expected 4 bytes read, got %d", numBytes)
	}

	expected := []byte{0x11, 0x22, 0x33, 0x44}
	for i := range expected {
		if readBuf[i] != expected[i] {
			t.Fatalf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], readBuf[i])
		}
	}
}

func TestBufferAccessorReadBytesIgnoresMemSpace(t *testing.T) {
	acc := NewBufferAccessor(0x1000, []byte{0x11, 0x22, 0x33, 0x44})
	acc.SetMemSpace(ocsd.MemSpaceEL1N)

	buf := make([]byte, 4)
	read := acc.ReadBytes(0x1000, ocsd.MemSpaceEL3, 0, 4, buf)
	if read != 4 {
		t.Fatalf("expected 4 bytes, got %d", read)
	}
	if binary.LittleEndian.Uint32(buf) != 0x44332211 {
		t.Fatalf("unexpected data: %x", buf)
	}
}

func TestCallbackAccessorReadBytesDelegatesWithoutPrefilter(t *testing.T) {
	cbAcc := NewCallbackAccessor(0x1000, 0x1FFF, ocsd.MemSpaceEL1N)
	called := false
	cbAcc.SetCallback(func(address ocsd.VAddr, memSpace ocsd.MemSpaceAcc, reqBytes uint32, buffer []byte) uint32 {
		called = true
		copy(buffer, []byte{0xAB, 0xCD})
		return 2
	})

	buf := make([]byte, 2)
	read := cbAcc.ReadBytes(0x2000, ocsd.MemSpaceEL3, 0, 2, buf)
	if !called {
		t.Fatalf("expected callback to be invoked")
	}
	if read != 2 {
		t.Fatalf("expected 2 bytes, got %d", read)
	}
	if buf[0] != 0xAB || buf[1] != 0xCD {
		t.Fatalf("unexpected callback data: %x", buf)
	}
}

func TestPrioritizationSwitchesFromAnyToSpecific(t *testing.T) {
	mapper := NewGlobalMapper()

	dataAny := make([]byte, 0x1000)
	for i := range dataAny {
		dataAny[i] = 0xAA
	}
	accAny := NewBufferAccessor(0, dataAny)
	accAny.SetMemSpace(ocsd.MemSpaceAny)
	mapper.AddAccessor(accAny, 0)

	dataSpec := make([]byte, 0x1000)
	for i := range dataSpec {
		dataSpec[i] = 0x55
	}
	accSpec := NewBufferAccessor(0, dataSpec)
	accSpec.SetMemSpace(ocsd.MemSpaceEL1N)
	mapper.accessors = append(mapper.accessors, accSpec)

	numBytes := uint32(1)
	buf := make([]byte, 1)

	_, _ = mapper.Read(0x0, 0, ocsd.MemSpaceEL3, numBytes, buf)
	if buf[0] != 0xAA {
		t.Fatalf("expected Any accessor on first read, got 0x%X", buf[0])
	}

	_, _ = mapper.Read(0x0, 0, ocsd.MemSpaceEL1N, numBytes, buf)
	if buf[0] != 0x55 {
		t.Fatalf("expected specific accessor after Any cached current, got 0x%X", buf[0])
	}
}
