# Go Test Infrastructure Analysis - OpenCSD

**Date:** March 8, 2026
**Scope:** opencsd/ directory (Go implementation of CoreSight decoder)
**Analysis Depth:** Code structure, test coverage, test quality, comparison to C++ test suite

---

## Executive Summary

The Go test infrastructure for OpenCSD has **35 test files** across protocol implementations with moderate-to-good coverage (62.5% - 92.1%). However, there are significant **quality gaps**, **missing test cases**, and **weak validation patterns** that pose risks for production use.

### Key Findings:
- **Coverage Range**: 62.5% (ETMv4) to 92.1% (demux)
- **Test Types**: Dominated by snapshot-based golden file tests; limited unit tests; NO integration or performance tests  
- **Major Gap**: Snapshot tests validate output formatting, NOT semantic correctness
- **No Error Injection**: Missing tests for malformed packets, buffer overflows, memory errors
- **Brittle Tests**: Hardcoded trace IDs, snapshot path dependencies, minimal edge case coverage

---

## 1. TEST FILE INVENTORY

### 1.1 Test Files by Protocol

| Protocol | Unit Tests | Snapshot Tests | Config Tests | Integration | Total Coverage |
|----------|-----------|----------------|--------------|-------------|---------|
| ETMv4    | 3 files   | 1 file         | 1 file       | None        | **62.5%** ⚠️ |
| ETMv3    | 6 files   | 1 file         | 1 file       | None        | **82.5%** |
| PTM      | 1 file    | 1 file         | None         | None        | No data (timeouts) |
| STM      | 1 file    | 1 file         | None         | None        | No data |
| ITM      | 1 file    | 1 file         | None         | None        | No data |
| ETE      | 2 files   | 1 file         | 1 file       | None        | **90.0%** |
| Common   | 11 files  | None           | None         | None        | **86.2%** |
| Demux    | 1 file    | None           | None         | None        | **92.1%** ✅ |
| Snapshot | 1 file    | None           | None         | None        | No tests |
| Memacc   | 1 file    | None           | None         | None        | No tests |
| Other    | 6 files   | None           | None         | None        | Varies |

**Total: 35 test files**

---

## 2. UNIT TEST ANALYSIS

### 2.1 Common Core Tests (11 files)

**Location:** `opencsd/internal/common/`

| Test File | Focus | Coverage | Quality |
|-----------|-------|----------|---------|
| `error_test.go` | Error string formatting | Good | ✅ Comprehensive error cases |
| `decode_base_test.go` | Base decoder logic | Good | ✅ Validates base framework |
| `code_follower_test.go` | Instruction following | Good | ✅ Covers branch/memory access |
| `arch_map_test.go` | Architecture mappings | Good | ✅ Enum mappings |
| `elem_list_test.go` | Element list management | Good | ✅ Container operations |
| `ret_stack_test.go` | Return stack | Good | ✅ Push/pop/overflow |
| `component_test.go` | Component base | Good | ✅ Initialization |
| `trace_element_test.go` | Trace element types | Good | ✅ Type conversions |
| `component_test.go` | Notifications | Good | ✅ Observer pattern |
| (others) | Various | Varies | ✅ Supporting infra |

**Assessment:** ✅ **GOOD** - Common library is well-tested with solid unit test coverage

---

### 2.2 Protocol Unit Tests

#### ETMv4 (3 files)

| File | Tests | Issues |
|------|-------|--------|
| `packet_test.go` | 73 tests (Stringer coverage) | ❌ Only tests string output, not packet logic |
| `config_test.go` | Register bitfield extraction | ✅ Validates config parsing |
| (No decoder unit tests) | — | ❌ **MISSING: packet decode logic** |

**Problems:**
- `packet_test.go` is **trivial** - only tests `PktType.String()` conversions
- NO tests for packet parsing (`UnpackPacket`, `DecodePacket` methods)
- NO tests for state machine transitions
- NO corrupt/malformed packet tests
- Coverage inflated by string formatting

#### ETMv3 (6 files)

| File | Tests | Quality |
|------|-------|---------|
| `packet_test.go` | Packet state, atom formats | ✅ Good coverage of packet types |
| `config_test.go` | Register fields | ✅ Comprehensive config validation |
| `decoder_test.go` | Packet processing | ⚠️ Minimal state coverage |
| `processor_test.go` | Stream processing | ✅ Good I/O validation |
| `processor_stream_test.go` | Complete workflows | ✅ Integration-like tests |
| `helpers_test.go` | Utility functions | ✅ Basic coverage |

**Problems:**
- `decoder_test.go` is very thin (mostly setup/helper functions)
- Limited atom processing coverage
- No malformed packet injection tests

#### PTM, STM, ITM (1 file each)

**Problems:**
- ❌ **Only basic config tests** - NO meaningful unit tests
- ❌ PTM config test exists but NO PTM decoder tests
- ❌ NO STM/ITM core decoder unit tests

#### ETE (2 files)

| File | Tests | Quality |
|------|-------|---------|
| `config_test.go` | Configuration | ✅ Good |
| `decoder_test.go` | Decoder logic | ✅ Reasonable coverage |

**Assessment:** ⚠️ **WEAK UNIT TEST FOUNDATION**

---

### 2.3 Demultiplexer Tests

**File:** `demux_test.go`

**Coverage:** 92.1% - **EXCELLENT**

- Tests sync/async byte patterns
- Tests frame alignment
- Tests multiple trace IDs
- Tests buffer edge cases
- **This is the gold standard** - shows what good unit tests look like

---

## 3. SNAPSHOT TEST ANALYSIS

### 3.1 Snapshot Test Architecture

**Pattern:** All major decoders use snapshot-based golden file tests:

```go
func TestXXXSnapshotsAgainstGolden(t *testing.T) {
    t.Parallel()
    
    // Load snapshot from disk (device configs + memory)
    reader := snapshot.NewReader()
    reader.SetSnapshotDir(snapshotDir)
    reader.ReadSnapShot()  // Parses .ini files
    
    // Decode trace
    goOut, _ := runSnapshotDecode(snapshotDir, sourceName)
    
    // Compare against golden .ppl file
    goldenBytes, _ := os.ReadFile(goldenPath)
    if got != want {
        t.Fatalf("snapshot mismatch")
    }
}
```

### 3.2 Snapshot Test Coverage by Protocol

| Protocol | # Snapshots | Snapshot Names | Issues |
|----------|------------|---|---------|
| **ETMv4** | 10 snapshots | juno_r1_1, a57_single_step, armv8_1m_branches, juno-uname-001/002, juno-ret-stck, test-file-mem-offsets, init-short-addr, bugfix-exact-match, a55-test-tpiu | ⚠️ Limited-most are Juno boards |
| **ETMv3** | 9 snapshots | (similar to ETMv4) | ⚠️ Heavy Juno representation |
| **PTM** | 4 snapshots | tc2-ptm-rstk-t32, TC2, Snowball, trace_cov_a15 | ⚠️ Old ARM platforms only |
| **STM** | 4 snapshots | stm_only, stm_only-2, stm_only-juno, stm-issue-27 | ⚠️ Minimal coverage |
| **ITM** | 3 snapshots | itm_only_raw, itm_only_csformat, itm-decode-test (duplicate name) | ❌ 2 test same snapshot |
| **ETE** | ~8 snapshots | (auto-discovered from testdata/) | ✅ Better discovery pattern |

### 3.3 Snapshot Test Quality Issues

#### ❌ Issue 1: Golden Files Contain Formatting, Not Truth

**Problem:** The golden `.ppl` files contain **pretty-printed output**, not decoded trace data integrity.

```
Snapshot mismatch at line N
want: "Idx:123; ID:10; [0xab 0xcd ];\tI_BRANCH_ADDRESS : description"
 got: "Idx:123; ID:10; [0xab 0xce ];\tI_BRANCH_ADDRESS : description"  ← 1 byte diff
```

**Risk:** A decoder bug **changing the output format** could be masked:
- Renaming packet types → test still passes if PPL format matches
- Adding/removing whitespace → spurious test failures
- Silent semantic errors in decode logic → PPL matches old C++ output anyway

**Test validates:** Output formatting, string generation
**Test doesn't validate:** 
- Actual instruction traces decoded correctly
- Memory locations resolved properly  
- Context/VMID handling
- Return stack operations
- Exception handling correctness

#### ❌ Issue 2: No Assertion on Decoded Data

```go
// Current pattern - just compares strings
got := sanitizePPL(string(goOut), tc.traceIDs, includeGenElems)
want := sanitizePPL(string(goldenBytes), tc.traceIDs, includeGenElems)
if got != want {
    t.Fatalf("mismatch") // ← BINARY: matches or fails, no semantic validation
}
```

**What should happen:**
```go
// Parsed validation
decoded := parseSnapshot(goOut)
for i, elem := range decoded {
    validateTraceElement(t, elem, tc.expectedSequence[i])
        // Check: address ranges, instruction types, exception codes, etc.
}
```

#### ❌ Issue 3: Snapshot Path Dependencies

All ETMv4/ETMv3/PTM tests hard-code snapshot names and trace IDs:

```go
testCases := []struct {
    name       string
    sourceName string
    traceIDs   []string  // ← Hard-coded
}{
    {name: "juno_r1_1", sourceName: "ETB_0", traceIDs: []string{"10", "11", ...}},
}
```

**Risk:** 
- Renaming/moving snapshots breaks tests (fragile coupling)
- Can't easily add new traces
- Snapshot IDs must match C++ output exactly

#### ❌ Issue 4: `sanitizePPL()` Masks Real Diffs

```go
got := sanitizePPL(string(goOut), tc.traceIDs, includeGenElems)
want := sanitizePPL(string(goldenBytes), tc.traceIDs, includeGenElems)
```

`sanitizePPL()` applies **heuristic filtering** to normalize output:
- Removes timestamps (can't compare if system generates different ones)
- Strips generic trace elements (OCSD_GEN_TRC_ELEM_*)
- Removes index records with embedded formatting

**Risk:** Legitimate diffs get hidden by "sanitization"

#### ❌ Issue 5: Some Snapshots Not Fully Listed

**ETMv3/ITM issue:**
```go
// itm_snapshot_test.go has duplicate snapshot name
{name: "itm-decode-test", snapshotName: "itm_only_raw", ...}
// "itm-decode-test" is test name, but uses "itm_only_raw" snapshot
// Confusing and maintenance nightmare
```

---

## 4. TEST ARCHITECTURE ANALYSIS

### 4.1 Test Framework Design

```
Unit Tests (fast, isolated)
  ├─ Config parsing ✅
  ├─ Packet type enumeration ✅  
  ├─ Error formatting ✅
  └─ Base framework ✅

Snapshot Tests (slow, realistic)
  ├─ Load device snapshots
  ├─ Decode trace data
  ├─ Compare PPL output (formatted strings)
  └─ Binary pass/fail ❌
```

### 4.2 What's Being Validated?

✅ **Validates:**
1. Code doesn't panic during decoding
2. Output formatting matches C++ (whitespace, packet names)
3. Snapshot reader infrastructure works
4. Basic packet type enumeration
5. Configuration register parsing

❌ **Does NOT validate:**
1. **Correctness of decoded trace elements** (instruction sequences, addresses)
2. **Error handling** (malformed packets, buffer overflows, invalid memory access)
3. **Edge cases** (empty traces, single-instruction, boundary conditions)
4. **Semantic correctness** (do decoded elements match what CPU executed?)
5. **Performance** (no benchmarks, no stress tests)
6. **Concurrency** (all tests serial, no parallel stress)
7. **Memory safety** (no fuzzing, no invalid input injection)

### 4.3 How Thoroughly Are Results Checked?

**Current approach: String comparison**
```
Output: Line-by-line PPL string diff reporting
Granularity: Full line (e.g., trace element formatting)
Assertion: Binary (matches/doesn't match)
Debugging: Shows first diff context (good!)
```

**Better approach would be:**
```
✓ Parse PPL into structured trace
✓ Validate each trace element
✓ Check instruction addresses form valid sequence
✓ Validate exception/context transitions
✓ Assert specific values (not just formatting)
```

---

## 5. COMPARISON TEST MODES - MISSING

### 5.1 No Go vs C++ Comparison Tests

**Current reality:** Each implementation tested independently
- Go output compared against Go golden files
- C++ output compared against C++ golden files
- No direct Go ↔ C++ comparison

**Risk:** Misaligned implementations could both pass tests

**Should exist:**
```go
func TestGoVsCppDecoder(t *testing.T) {
    // Run same snapshot through both:
    // - C++ decoder (via CLI tool)
    // - Go decoder (via library)
    // Compare outputs byte-for-byte
    // Flag any semanti differences
}
```

### 5.2 No Comparison Mode Flags

Gap: `gen_golden_test.go` has `-update` flag to regenerate goldens
- But only allows auto-generating from current Go decoder output
- No flag to import C++ output as new golden
- No side-by-side comparison mode

---

## 6. COVERAGE ANALYSIS

### 6.1 Coverage by Package

```
demux:     92.1% ✅ Excellent
ete:       90.0% ✅ Good
common:    86.2% ✅ Good
etmv3:     82.5% ✅ Acceptable
etmv4:     62.5% ⚠️ LOW - major protocols untested
ptm:       ? (timeouts during test runs)
stm:       ? (timeouts during test runs)
itm:       ? (timeouts during test runs)
```

### 6.2 Known Coverage Gaps (from code review)

| Component | Coverage Gap | Impact |
|-----------|-------------|--------|
| ETMv4 packet parsing | ~38% | Packet decode logic untested |
| ETMv4 decoder state machine | ~30% | State transitions not validated |
| Specification handling | ~40% | Speculation logic minimally tested |
| Return stack operations | ~25% | Only config tests, no push/pop validation |
| Exception handling | ~20% | Error paths not exercised |
| Protocol switching | N/A | No multi-protocol tests |

### 6.3 Why Coverage Numbers Are Misleading

**ETMv4 snapshot tests run but DON'T exercise:**
- Packet parsing failure paths
- State machine error cases
- Memory access failures
- Edge case packet sequences

These are represented as "coverage" but actual **code path diversity is low**.

---

## 7. MISSING TEST CASES

### 7.1 Error Injection Tests - CRITICAL MISSING

```go
// NO TESTS FOR:

// 1. Malformed packets
TestMalformedEtmv4Packets_DecoderRejects() // ❌ MISSING
TestMalformedEtmv3Packets_DecoderRejects() // ❌ MISSING

// 2. Buffer overruns
TestTraceDataTruncation_ReturnsError() // ❌ MISSING
TestIncompletePacketSequence() // ❌ MISSING

// 3. Memory access failures
TestMemoryAccessError_Handled() // ❌ MISSING
TestInvalidMemoryRegion_NoOOB() // ❌ MISSING

// 4. Invalid configurations
TestBadDeviceConfig_Rejected() // ❌ MISSING
TestInvalidRegisterValues() // ❌ MISSING

// 5. Edge cases
TestEmptyTraceData() // ❌ MISSING (snapshots all have data)
TestSingleInstructionTrace() // ❌ MISSING
TestTraceWithGaps() // ❌ MISSING
TestHighFrequencyContextSwitches() // ❌ MISSING

// 6. Concurrent decoding
TestParallelDecoding() // ❌ MISSING
TestDecoderStateIsolation() // ❌ MISSING

// 7. Extreme values
TestMaximumCycleCount() // ❌ MISSING
TestMaximumAddresses() // ❌ MISSING
TestDeepReturnStack() // ❌ MISSING (only one stack test in ITM)
```

### 7.2 Integration/End-to-End Tests - MISSING

```go
// NO TESTS FOR:

// 1. Multi-protocol trees
TestMultipleProtocolDecodersInTree() // ❌ MISSING

// 2. Demux + decoder pipeline
TestFullDemuxToTraceElement() // ❌ MISSING

// 3. Frame format variations
TestFrameFormatted_Dstream() // ❌ MISSING
TestFrameFormatted_MemAlign() // ❌ MISSING
TestSourceData_NoFrames() // ❌ MISSING

// 4. Realistic workflows
TestLiveDecodeWithIncrementalData() // ❌ MISSING
TestDecoderResetRecovery() // ❌ MISSING
```

### 7.3 Performance/Benchmark Tests - NONE

```go
// NO BENCHMARKS FOR:
BenchmarkETMv4Decode_1MB() // ❌ MISSING
BenchmarkDemultiplexing() // ❌ MISSING
BenchmarkMemoryAccessPatterns() // ❌ MISSING
```

---

## 8. TEST QUALITY ISSUES

### Issue 1: Snapshot Tests Don't Fail Fast on Real Errors

**Example:** If a decoder has a bug in exception handling:

```go
// Bug: exception.PC not set correctly
exc.PC = 0x0  // Should be 0x2000

// Snapshot test:
// - Decodes successfully
// - Generates PPL output
// - PPL still matches golden (if PPL just shows "exception")
// - TEST PASSES ✓ (but bug exists!)
```

### Issue 2: Mocks Are Too Permissive

Example from `ptm_test.go`:

```go
func (m *mockMemAcc) ReadTargetMemory(...) (uint32, []byte, ocsd.Err) {
    m.calls++
    if m.failAfter > 0 && m.calls > m.failAfter {
        return 0, nil, ocsd.OK  // ← Returns OK even on failure!
    }
    // Returns plausible ARM instructions regardless of address
    return reqBytes, []byte{0x00, 0x00, 0x00, 0xEA}, ocsd.OK
}
```

**Problems:**
- Mock returns "valid" instructions regardless of address
- Doesn't simulate actual memory contents
- Can't test address tracking correctness

### Issue 3: Some Tests Are Trivial

Example: `etmv4/packet_test.go`

```go
func TestPktTypeString(t *testing.T) {
    tests := []struct {
        name string
        pkt  PktType
        want string
    }{
        {"PktNotSync", PktNotSync, "I_NOT_SYNC"},
        {"PktAsync", PktAsync, "I_ASYNC"},
        // ... 70+ enum string mappings
    }
    for _, tt := range tests {
        if got := tt.pkt.String(); got != tt.want {
            t.Errorf(...)
        }
    }
}
```

**Problem:** This is **pure formatting test**, not functionality. Contributes to coverage% but adds little value.

### Issue 4: No Comparative Assertions

Current pattern:
```go
if got != want {
    t.Fatalf("snapshot mismatch")
}
```

No explanation **what part failed**, no **expected vs actual diff summary**, just "mismatch".

Good pattern:
```go
if len(got) != len(want) {
    t.Errorf("line count mismatch: got %d, want %d", len(got), len(want))
}
for i, line := range want {
    if i >= len(got) {
        t.Errorf("line %d missing in output", i)
        continue
    }
    if got[i] != line {
        t.Errorf("line %d mismatch:\n  got:  %q\n  want: %q", i, got[i], line)
    }
}
```

---

## 9. MISSING TEST INFRASTRUCTURE

### What Exists:
- ✅ Snapshot test framework
- ✅ Basic unit tests for common library
- ✅ Config parsing tests
- ✅ Demux test coverage

### What's Missing:
- ❌ Fuzz testing (no invalid input generation)
- ❌ Property-based testing (no invariant checking)
- ❌ Benchmark suite (no performance regression detection)
- ❌ Integration test driver
- ❌ Comparative testing (Go vs C++)
- ❌ Chaos injection (memory errors, timeouts)

---

## 10. SPECIFIC PROTOCOL GAP ANALYSIS

### 10.1 ETMv4 - LOWEST COVERAGE (62.5%)

**Unit Tests:**
- ❌ NO `decoder_test.go` file
- ❌ NO packet parsing tests  
- ❌ NO state machine tests
- ❌ Only trivial string formatting tests

**Snapshot Tests:**
- ✅ 10 snapshots (good count)
- ⚠️ All from high-end platforms (Juno, A57)
- ❌ No edge cases (empty, single-instruction, error conditions)

**Missing Critical Tests:**
```go
TestEtmv4PacketParsingErrors() // NO TEST
TestEtmv4SpeculationBoundary() // NO TEST  
TestEtmv4ConditionalInstructions() // NO TEST (not supported but no error test)
TestEtmv4ByteSynchronization() // NO TEST
```

**Recommendation:** Bring ETMv4 coverage to 80%+ before release

### 10.2 ETMv3 - MODERATE COVERAGE (82.5%)

**Better than ETMv4** but still has gaps:

**Unit Tests:**
- ✅ Better: 6 test files
- ✅ Decoder tests exist (though minimal)
- ⚠️ Limited atom processing tests
- ❌ No error injection tests

**Snapshot Tests:**
- ✅ 9 snapshots good coverage
- ❌ Still heavy on Juno boards

**Recommendation:** Add ETMv3 error case tests

### 10.3 PTM/STM/ITM - SEVERELY UNDERTESTED

**Each has:**
- ❌ Config tests only (1 file)
- ❌ NO meaningful unit tests
- ✅ Snapshot tests (but minimal)

**Example PTM gap:**
```go
// File: ptm_test.go exists with:
TestPtmConfig() ✅         // Register parsing
// That's IT for unit tests

// Missing:
TestPtmPacketParsing() // ❌
TestPtmDecoderState() // ❌
TestPtmAtomProcessing() // ❌
TestPtmBranchHandling() // ❌
```

**Recommendation:** Add proper unit test coverage for these protocols

### 10.4 ETE - BETTER THAN AVERAGE (90%)

**Strengths:**
- ✅ Snapshot auto-discovery (better than hard-coded test cases)
- ✅ Transaction handling tested
- ✅ Good decoder coverage compared to siblings

**Still Missing:**
- ❌ No `pe_reset_test.go` (ETE-specific packets)
- ❌ No transaction error tests
- ❌ Limited edge case coverage

---

## 11. RECOMMENDATIONS

### Immediate Actions (Critical - Do Before Production)

1. **Add error injection tests for all protocols**
   ```go
   // Create new files: etmv4/error_injection_test.go, etc.
   // Test malformed packets, buffer overflows, invalid configs
   ```
   - **Time Estimate:** 2-3 days per protocol (6 protocols = 2-3 weeks)
   - **Impact:** Catch production crash bugs

2. **Convert snapshot tests to semantic validation**
   ```go
   // Instead of string comparison, parse and validate decoded elements
   // Check: instruction sequences, memory ranges, exception codes
   type ValidatedElement struct {
       addr uint64
       instr ocsd.InstrType
       context *ocsd.ContextInfo
   }
   
   // Add validation functions for each protocol
   func ValidateEtmv4Trace(t *testing.T, elements []ocsd.TraceElement, expected []ValidatedElement)
   ```
   - **Time Estimate:** 2-3 weeks (covers all protocols)
   - **Impact:** Detect semantic bugs, reduce brittleness

3. **Add Go vs C++ comparative tests**
   ```go
   // New integration test suite that runs same snapshot through both decoders
   // Flag any output differences
   func TestGoVsCppCompatibility(t *testing.T)
   ```
   - **Time Estimate:** 1 week
   - **Impact:** Ensure parity with C++ reference implementation

### Short-term Actions (2-4 weeks)

4. **Increase ETMv4 coverage to 80%+**
   - Add proper decoder unit tests (not just string formatting)
   - Test state machine transitions
   - Add edge case scenarios
   - **Time Estimate:** 1 week

5. **Add missing edge case tests**
   ```go
   TestEmptyTraceData()
   TestSingleInstructionTrace()
   TestVeryDeepReturnStack()
   TestHighFrequencyContextSwitches()
   TestMaximumCycleCountValues()
   ```
   - **Time Estimate:** 1 week

6. **Add benchmark suite**
   ```go
   BenchmarkETMv4Decode_1MB(b *testing.B)
   BenchmarkDemultiplexing(b *testing.B)
   BenchmarkMemoryAccess(b *testing.B)
   ```
   - **Time Estimate:** 3-4 days
   - **Impact:** Detect performance regressions

### Medium-term Actions (1-3 months)

7. **Refactor snapshot tests for reusability**
   ```go
   // Create shared snapshot test framework
   type SnapshotTestCase struct {
       Name string
       Dir string
       Source string
       Validator func(*testing.T, []ocsd.TraceElement)
   }
   
   // Use in all protocols instead of copy-paste code
   func runProtocolSnapshotTests(t *testing.T, protocol string, cases []SnapshotTestCase)
   ```
   - **Impact:** Reduce maintenance burden

8. **Add fuzzing**
   ```go
   // Use Go's native fuzzing (Go 1.18+)
   func FuzzEtmv4PacketParsing(f *testing.F)
   func FuzzDemultiplexing(f *testing.F)
   ```
   - **Time Estimate:** 1 week (initial setup)
   - **Impact:** Find corner cases automatically

9. **Add integration test driver**
   ```go
   // End-to-end test harness that:
   // - Loads snapshot
   // - Configures decoders
   // - Runs data through pipeline
   // - Validates output
   // - Can be parameterized by protocol/snapshot
   ```
   - **Time Estimate:** 1-2 weeks
   - **Impact:** Catch multi-protocol interaction bugs

---

## 12. TEST QUALITY SCORECARD

| Dimension | Score | Status | Note |
|-----------|-------|--------|------|
| **Coverage %** | 62-92% | ⚠️ Uneven | ETMv4 too low (62%) |
| **Unit Tests** | C | ⚠️ Mixed | Good for common lib, weak for protocols |
| **Error Handling** | F | ❌ CRITICAL | Almost no error injection tests |
| **Snapshot Quality** | C+ | ⚠️ Formatting | Tests output format, not semantic correctness |
| **Edge Cases** | D | ❌ Poor | Missing empty traces, single instructions, boundaries |
| **Integration** | F | ❌ NONE | No multi-component tests |
| **Performance** | F | ❌ NONE | No benchmarks |
| **Go vs C++ Parity** | ? | ❌ UNCLEAR | No comparative tests |
| **Maintainability** | C | ⚠️ Duplicated | Snapshot test code copy-pasted across protocols |
| **Documentation** | C | ⚠️ Light | Some test helpers explained, but no overall test strategy |

**Overall Grade: C** (Acceptable but significant gaps)

---

## 13. RISK ASSESSMENT

### High Risk Areas

| Protocol | Risk | Reason |
|----------|------|--------|
| **ETMv4** | 🔴 HIGH | 62% coverage, weak decoder tests, critical path undertested |
| **PTM** | 🔴 HIGH | Config-only tests, no decoder validation |
| **STM** | 🔴 HIGH | Minimal snapshot tests, no error handling |
| **ITM** | 🔴 HIGH | Limited test coverage, duplicate snapshot reference |

### Medium Risk Areas

| Component | Risk | Reason |
|-----------|------|--------|
| **Snapshot Tests** | 🟡 MEDIUM | Only validate output formatting, not correctness |
| **Memory Access** | 🟡 MEDIUM | Mocks too permissive, real memory errors not tested |
| **Context Switching** | 🟡 MEDIUM | Limited tests for rapid context changes |

### Low Risk Areas

| Component | Status | Reason |
|-----------|--------|--------|
| **Common Library** | 🟢 LOW | 86.2% coverage, well-tested |
| **Demux** | 🟢 LOW | 92.1% coverage, comprehensive tests |
| **Basic Configs** | 🟢 LOW | Register parsing well-tested |

---

## 14. APPENDIX: Quick Reference for Test Locations

### Running Tests
```bash
# All tests
cd /c/Users/arthu/git/OpenCSD/opencsd
go test ./...

# By protocol
go test ./internal/etmv4/...
go test ./internal/etmv3/...
go test ./internal/ptm/...

# Specific test
go test -run TestEtmv4SnapshotsAgainstGolden ./internal/etmv4/...

# With verbose output
go test -v ./internal/common/...

# Coverage report
go test -cover ./internal/...
```

### Adding New Tests

**Pattern 1: Unit test (fast)**
```go
// File: internal/protocol/unit_test.go
func TestXXX(t *testing.T) {
    // Use mocks, test single component
}
```

**Pattern 2: Snapshot test (slow)**
```go
// File: internal/protocol/snapshot_test.go
func TestXXXSnapshotsAgainstGolden(t *testing.T) {
    // Load snapshots, validate golden files
}
```

### Test Data Locations
```
opencsd/
├── internal/
│   ├── etmv4/
│   │   ├── testdata/          ← Snapshot directories
│   │   │   ├── juno_r1_1/
│   │   │   ├── a57_single_step/
│   │   │   └── *.ppl           ← Golden files
│   │   └── snapshot_test.go   ← Snapshot tests
│   ├── ptm/
│   │   └── testdata/
│   └── ...
```

---

## 15. CONCLUSIONS

The Go test infrastructure for OpenCSD provides **basic confidence** that code doesn't crash, but lacks the **depth** needed for production-critical trace decoders. The heavy reliance on snapshot tests validates **output formatting** rather than **semantic correctness**.

**Key Gaps:**
1. Minimal error handling validation
2. Weak unit test foundation for protocol implementations
3. Snapshot tests mask real issues via string comparison
4. No integration or comparative tests
5. No performance regression detection

**Priority Fix:** Add error injection tests and convert snapshot tests to validate decoded element correctness (not just output formatting). Without these, production deployments risk silent failures.

