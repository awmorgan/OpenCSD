# OpenCSD Go Test Infrastructure - Recommended Actions

## Priority Matrix

```
IMPACT/EFFORT QUADRANT:
                    HIGH IMPACT
                         ↑
        [Quick Wins] │ [Major Projects]
                 ←───┼───→
        [Time Wasters]│ [Support Work]
                         ↑
                    HIGH EFFORT
```

---

## ACTION 1: Error Injection Test Suite (CRITICAL)

### Goal
Systematically test error paths and edge cases for all protocols.

### Why Critical
- **Risk:** Without error tests, decoder crashes in production go undetected
- **Impact:** Could hang/crash trace capture on real hardware
- **Confidence:** Tests currently validate "happy path" only

### Scope
Create error test files for: ETMv4, ETMv3, PTM, STM, ITM, ETE

### Implementation Plan

#### Step 1.1: Create Error Test Generator (1-2 hours)
Create helper utilities for test files:

**File: `internal/testing/error_helpers.go` (NEW)**
```go
package testhelpers

import "opencsd/internal/ocsd"

// MalformedPacket generates invalid packet bytes
func MalformedPacket(packetType string) []byte {
    switch packetType {
    case "truncated":
        return []byte{0xFF}  // Incomplete sync packet
    case "invalid_length":
        return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // Bad length
    // ... 10-15 patterns per protocol
    }
}

// MockMemoryError simulates memory access failures
func MockMemoryError(failAfter int) common.TargetMemAccess {
    return &mockMemWithErrors{failAfter: failAfter}
}

// func ValidateError(t *testing.T, resp ocsd.DatapathResp, expected ocsd.Err)
// func ExpectPanic(t *testing.T, fn func(), message string)
```

#### Step 1.2: ETMv4 Error Tests (3 days)

**File: `internal/etmv4/error_injection_test.go` (NEW)**

```go
package etmv4

import (
    "testing"
    "opencsd/internal/ocsd"
)

func TestMalformedPackets_DecoderRejects(t *testing.T) {
    tests := []struct {
        name       string
        rawBytes   []byte
        expectErr  ocsd.Err
    }{
        // Truncated ASYNC
        {
            name:      "truncated_async",
            rawBytes:  []byte{0xFF, 0x7F},  // Missing byte
            expectErr: ocsd.ErrBadPacketLen,
        },
        // Invalid trace info
        {
            name:      "bad_trace_info",
            rawBytes:  []byte{0x00, 0xBB, ...},
            expectErr: ocsd.ErrBadTraceMode,
        },
        // Malformed cycle count
        // Malformed address
        // etc. (15-20 cases)
    }
    
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            proc := createTestProcessor()
            _, resp, err := proc.TraceDataIn(ocsd.OpData, 0, tc.rawBytes)
            
            if err != tc.expectErr {
                t.Errorf("expected error %v, got %v", tc.expectErr, err)
            }
            // Decoder should either return error OR not panic
            if ocsd.DataRespIsFatal(resp) {
                t.Errorf("unexpected fatal response: %v", resp)
            }
        })
    }
}

func TestBufferOverrun_Protection(t *testing.T) {
    proc := createTestProcessor()
    
    // Extremely large trace data - should handle gracefully
    largeData := make([]byte, 1024*1024*100)  // 100MB
    
    // Should timeout or complete, NOT crash
    processed, resp, err := proc.TraceDataIn(ocsd.OpData, 0, largeData)
    
    if processed < 0 {
        t.Errorf("invalid processed count: %d", processed)
    }
    // Should eventually return Wait or complete normally
}

func TestMemoryAccessError_Handled(t *testing.T) {
    config := createTestConfig()
    dec := createDecoder(config)
    
    // Attach mock that fails after N calls
    dec.MemAccess.Attach(testhelpers.MockMemoryError(failAfter: 5))
    
    // Process ISync + branch that requires memory access
    pkt := createISync()
    dec.PacketDataIn(ocsd.OpData, 0, pkt)
    
    branchPkt := createBranchAddress()
    resp := dec.PacketDataIn(ocsd.OpData, 1, branchPkt)
    
    // Should handle gracefully, not crash
    if ocsd.DataRespIsFatal(resp) && resp != ocsd.RespFatalNotInit {
        t.Errorf("unexpected fatal error: %v", resp)
    }
}

func TestInvalidConfiguration_Rejected(t *testing.T) {
    tests := []struct {
        name     string
        config   *Config
        expectOK bool
    }{
        {name: "nil_config", config: nil, expectOK: false},
        {name: "zero_config", config: &Config{}, expectOK: false},
        {name: "invalid_idr", config: &Config{RegIdr0: 0xFFFFFFFF}, expectOK: false},
    }
    
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            dec := createDecoder(tc.config)
            err := dec.SetTraceProtocolConfig(tc.config)
            
            if tc.expectOK && err != ocsd.OK {
                t.Errorf("expected OK, got %v", err)
            }
            if !tc.expectOK && err == ocsd.OK {
                t.Errorf("expected error for invalid config")
            }
        })
    }
}

func TestEdgeCase_EmptyTrace(t *testing.T) {
    proc := createTestProcessor()
    
    // No data
    processed, resp, err := proc.TraceDataIn(ocsd.OpData, 0, []byte{})
    
    if err != nil {
        t.Errorf("empty trace should not error: %v", err)
    }
    if processed != 0 {
        t.Errorf("empty trace should process 0 bytes")
    }
}

func TestEdgeCase_SingleInstructionTrace(t *testing.T) {
    // ... Test minimal valid trace sequence
}

func TestEdgeCase_DeepSpeculation(t *testing.T) {
    // Create max P0 stack depth (can be configurable based on ETMv4 variant)
    // Test speculation commits/cancels at depth limits
}
```

#### Step 1.3: Repeat for ETMv3, PTM, STM, ITM, ETE (8-10 days)
- Same pattern for each protocol
- Adjust packet formats per protocol
- Test protocol-specific edge cases

#### Step 1.4: Documentation (2-4 hours)
Add docstring to each error test file explaining:
- What errors are being tested
- Why each error case matters
- What production impact is prevented

### Estimate
- **Total Time:** 12-14 days
- **Files to Create:** 7 new test files
- **Tests to Add:** ~150-200 test cases

### Success Criteria
1. All 6 protocols have error_injection_test.go files
2. Each file covers: malformed packets, memory errors, config errors, edge cases
3. No unhandled panics in error paths
4. All error tests either pass or document expected failures

---

## ACTION 2: Snapshot Test Refactoring (HIGH VALUE)

### Goal
Convert snapshot tests from string comparison to semantic validation.

### Why Important
- **Current Issue:** Tests validate output formatting, not decoded trace correctness
- **Risk:** Silent semantic bugs hidden by passing tests
- **Value:** Increases confidence that decoded traces match actual execution

### Phase 1: Add Validation Layer (3 days)

**File: `internal/testing/snapshot_validators.go` (NEW)**

```go
package testhelpers

import (
    "opencsd/internal/ocsd"
    "testing"
)

// ValidatedTraceElement represents a semantically validated trace element
type ValidatedTraceElement struct {
    Type         ocsd.GenElemType
    Address      uint64
    LastAddress  uint64
    InstrType    ocsd.InstrType
    Context      *ocsd.ContextInfo
    Exception    *ocsd.ExceptionInfo
    IsValid      bool
    ErrorReason  string  // If not valid, why
}

// ParsePPLOutput parses pretty-printed output into trace elements
func ParsePPLOutput(ppl string) []ValidatedTraceElement {
    // Parse PPL format lines
    // Extract trace element info
    // Return structured data
}

// ValidateTraceSequence checks for logical errors
func ValidateTraceSequence(t *testing.T, elements []ValidatedTraceElement) {
    // Check 1: Instruction addresses monotonic within thread context
    for i := 1; i < len(elements); i++ {
        if shouldBeSequential(elements[i-1], elements[i]) {
            if elements[i].Address < elements[i-1].Address {
                t.Errorf("address went backwards: 0x%x -> 0x%x", 
                    elements[i-1].Address, elements[i].Address)
            }
            if elements[i].Address != elements[i-1].LastAddress {
                t.Errorf("address jump: 0x%x should be 0x%x (gap?)",
                    elements[i].Address, elements[i-1].LastAddress)
            }
        }
    }
    
    // Check 2: Context changes are valid
    // Check 3: Exception entries have matching returns/continuations
    // Check 4: Return stack under/overflow checks
    // etc.
}

// CheckContextValidity validates context/VMID changes
func CheckContextValidity(t *testing.T, elements []ValidatedTraceElement) {
    // After context change, all subsequent instructions should use new context
    // unless another context change occurs
}

// CheckReturnStack validates return stack operations
func CheckReturnStack(t *testing.T, elements []ValidatedTraceElement) {
    // Track return stack pushes/pops
    // Detect overflow conditions
    // Validate matched pairs
}
```

### Phase 2: Migrate ETMv4 Tests (2-3 days)

**File: `internal/etmv4/snapshot_test.go` (MODIFY)**

```go
// Current pattern (string comparison):
func TestETMv4SnapshotsAgainstGolden(t *testing.T) {
    // ...
    got := sanitizePPL(string(goOut), tc.traceIDs, includeGenElems)
    want := sanitizePPL(string(goldenBytes), tc.traceIDs, includeGenElems)
    if got != want {
        t.Fatalf("snapshot mismatch")
    }
}

// New pattern (semantic validation):
func TestETMv4SnapshotsSemantics(t *testing.T) {
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            snapshotDir := filepath.Join("testdata", tc.name)
            
            // Decode
            goOut, _ := runSnapshotDecode(snapshotDir, tc.sourceName, tc.packetOnly)
            
            // Parse into trace elements
            elements := testhelpers.ParsePPLOutput(string(goOut))
            
            // VALIDATE SEMANTICS
            testhelpers.ValidateTraceSequence(t, elements)
            testhelpers.CheckContextValidity(t, elements)
            testhelpers.CheckReturnStack(t, elements)
            
            // Optional: Check against expected snapshot signature
            assertSnapshotSignature(t, tc.name, elements)
        })
    }
}

// Keep old string-comparison test but mark it as secondary:
func TestETMv4SnapshotsFormatting(t *testing.T) {
    // String comparison (less important, but still useful for detecting formatting changes)
    // This should SKIP if semantic test passes
    t.Skip("deprecated - use TestETMv4SnapshotsSemantics + formatting only")
}
```

### Phase 3: Repeat for Other Protocols (3-4 days)
- ETMv3
- PTM
- STM
- ITM
- ETE

### Estimate
- **Total Time:** 8-10 days
- **Files to Create:** 1 validation library
- **Files to Modify:** 6 snapshot test files
- **Validators to Implement:** 8-10 functions

### Success Criteria
1. Validation library created and documented
2. All snapshot tests converted to use semantic validation
3. All tests still pass (no regression)
4. Validation catches at least one previously-hidden issue

---

## ACTION 3: Go vs C++ Comparative Tests (HIGH VALUE)

### Goal
Create tests that verify Go decoder produces identical output to C++ reference.

### Why Important
- **Risk:** Undetected divergence from C++ behavior
- **Value:** Guarantees behavioral parity

### Phase 1: Build Test Infrastructure (2-3 days)

**File: `tests/comparative_test.go` (NEW)**

```go
package tests

import (
    "os/exec"
    "bytes"
    "testing"
)

// RunCppDecoder runs C++ decoder via CLI (trc_pkt_lister)
func RunCppDecoder(snapshotDir, source string) ([]byte, error) {
    // Path to C++ built binary
    cppBinary := "../decoder/bin/trc_pkt_lister"  
    
    cmd := exec.Command(cppBinary, 
        "--snapshot", snapshotDir,
        "--source", source)
    
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    return out.Bytes(), err
}

// RunGoDecoder runs Go decoder via library call
func RunGoDecoder(snapshotDir, source string) ([]byte, error) {
    // ... wrap Go decoder
}

// CompareOutputs returns differences (if any)
func CompareOutputs(cppOut, goOut string) []string {
    cppLines := strings.Split(cppOut, "\n")
    goLines := strings.Split(goOut, "\n")
    
    diffs := []string{}
    for i := 0; i < max(len(cppLines), len(goLines)); i++ {
        var cppLine, goLine string
        if i < len(cppLines) {
            cppLine = cppLines[i]
        }
        if i < len(goLines) {
            goLine = goLines[i]
        }
        
        if cppLine != goLine {
            diffs = append(diffs, fmt.Sprintf(
                "Line %d diff:\n  C++: %q\n  Go:  %q", i+1, cppLine, goLine))
        }
    }
    return diffs
}

// ComparativeTestCase describes what to compare
type ComparativeTestCase struct {
    Name       string
    Snapshot   string
    Source     string
    AllowedDiffs int  // Some formatting differences OK
}

func TestComparative_GoVsCpp(t *testing.T) {
    cases := []ComparativeTestCase{
        {Name: "juno_r1_1", Snapshot: "juno_r1_1", Source: "ETB_0", AllowedDiffs: 0},
        {Name: "a57_single_step", Snapshot: "a57_single_step", Source: "CSTMC_TRACE_FIFO", AllowedDiffs: 0},
        // ... all snapshot cases
    }
    
    for _, tc := range cases {
        t.Run(tc.Name, func(t *testing.T) {
            cppOut, err := RunCppDecoder(tc.Snapshot, tc.Source)
            if err != nil {
                t.Fatalf("C++ decoder failed: %v", err)
            }
            
            goOut, err := RunGoDecoder(tc.Snapshot, tc.Source)
            if err != nil {
                t.Fatalf("Go decoder failed: %v", err)
            }
            
            diffs := CompareOutputs(string(cppOut), string(goOut))
            if len(diffs) > tc.AllowedDiffs {
                for _, diff := range diffs[:min(5, len(diffs))] {
                    t.Logf("DIFF: %s", diff)
                }
                t.Fatalf("Go vs C++ output mismatch: %d differences", len(diffs))
            }
        })
    }
}
```

### Phase 2: Build Infrastructure in CI (1-2 days)
- Verify C++ binary is available in test environment
- Set up fallback if C++ binary missing

### Estimate
- **Total Time:** 3-5 days
- **Files to Create:** 1 test file (comparative_test.go)
- **Functions to Implement:** 3-4 helpers

### Success Criteria
1. Comparative test infrastructure exists
2. Can run against all snapshots
3. Identifies any actual Go vs C++ differences
4. Continues to pass as implementations evolve

---

## ACTION 4: ETMv4 Coverage Improvement (MEDIUM PRIORITY)

### Goal
Increase ETMv4 coverage from 62% to 80%+ by adding proper decoder unit tests.

### Current State
- 62.5% coverage (lowest among protocols)
- Only trivial string formatting tests
- No decoder state machine tests
- Snapshot tests carry the load

### Implementation

**File: `internal/etmv4/decoder_unit_test.go` (NEW)**

```go
package etmv4

import (
    "testing"
    "opencsd/internal/ocsd"
    "opencsd/internal/idec"
)

// Helper to create minimal valid decoder state
func createInitializedDecoder(config *Config) *PktDecode {
    manager := NewDecoderManager()
    dec := manager.CreatePktDecode(0, config).(*PktDecode)
    dec.MemAccess.Attach(&mockMemAcc{})
    dec.InstrDecode.Attach(idec.NewDecoder())
    return dec
}

func TestDecoderStateTransitions(t *testing.T) {
    dec := createInitializedDecoder(&Config{})
    out := &testTrcElemIn{}
    dec.TraceElemOut.Attach(out)
    
    // Test: OpReset transitions decoder properly
    resp := dec.PacketDataIn(ocsd.OpReset, 0, nil)
    if resp != ocsd.RespCont {
        t.Errorf("Reset failed: %v", resp)
    }
    
    // Test: First packet must be ASYNC
    asyncPkt := &TracePacket{Type: PktAsync}
    resp = dec.PacketDataIn(ocsd.OpData, 0, asyncPkt)
    if resp != ocsd.RespCont {
        t.Errorf("Async processing failed: %v", resp)
    }
    
    // Test: ISync transitions to decode-ready state
    isyncPkt := &TracePacket{
        Type: PktTraceInfo,
        Addr: 0x1000,
    }
    resp = dec.PacketDataIn(ocsd.OpData, 1, isyncPkt)
    if resp == ocsd.RespFatalNotInit {
        t.Errorf("ISync failed: decoder not ready")
    }
}

func TestCommitPacketParsing(t *testing.T) {
    // Test commit packet generates trace elements
}

func TestCancelPacketHandling(t *testing.T) {
    // Test cancel F1/F2/F3 packets
}

func TestSpeculationDepthManagement(t *testing.T) {
    // Verify P0 stack management
}

func TestAtomExtraction(t *testing.T) {
    // Verify 6 atom formats properly extracted
}

func TestAddressPacketTypes(t *testing.T) {
    // Test all 8 address packet variants
    // Short/Long × ISA0/ISA1
}

func TestContextPackets(t *testing.T) {
    // Test context updates
}

func TestTimestampCycleCount(t *testing.T) {
    // Test CC formats F1/F2/F3
    // Test TS packets
}

// ... 15-20 more specific test functions

// Integration: Realistic packet sequence
func TestRealisticInstructionTrace(t *testing.T) {
    // Create valid: ASYNC → TraceInfo → Atoms → Branch → Exception → TraceOn
    // Verify trace elements generated at each step
}
```

### Estimate
- **Total Time:** 4-5 days
- **Files to Create:** 1 new test file
- **Test Functions:** 15-20

### Success Criteria
1. ETMv4 coverage increases to 75%+
2. All new tests pass
3. Decoder logic (not just formatting) is verified

---

## ACTION 5: Benchmark Suite (LOW PRIORITY - NICE TO HAVE)

### Goal
Establish performance baselines and detect regressions.

### File: `internal/benchmarks/benchmarks_test.go` (NEW)

```go
package benchmarks

import (
    "testing"
    "opencsd/internal/etmv4"
    "opencsd/internal/demux"
)

func BenchmarkETMv4Decode_1MB(b *testing.B) {
    // Create 1MB of trace data
    // Run decoder N times
}

func BenchmarkDemultiplexing_HighFrequency(b *testing.B) {
    // Multi-trace demux with high packet rate
}

func BenchmarkMemoryAccess_Random(b *testing.B) {
    // Random memory access patterns
}
```

### Estimate
- **Total Time:** 2-3 days
- **Benchmarks:** 3-5 key scenarios

---

## PRIORITIZED ACTION TIMELINE

### Phase 1: CRITICAL (Weeks 1-2)
- **Action 1:** Error Injection Tests
  - Week 1: Helpers + ETMv4
  - Week 2: Remaining protocols
- **Deliverable:** 7 error_injection_test.go files, ~200 test cases

### Phase 2: HIGH VALUE (Weeks 3-4)  
- **Action 2:** Snapshot Refactoring
  - Week 3: Validation library + ETMv4 migration
  - Week 4: Remaining protocols
- **Deliverable:** Semantic validation framework, all protocols migrated

### Phase 3: MEDIUM VALUE (Week 5)
- **Action 4:** ETMv4 Coverage
  - Add decoder_unit_test.go
- **Deliverable:** ETMv4 coverage 75%+

### Phase 4: HIGH VALUE (Week 6)
- **Action 3:** Comparative Tests
  - Build infrastructure
  - Run against all snapshots
- **Deliverable:** Go vs C++ parity verification

### Phase 5: OPTIONAL (After delivery)
- **Action 5:** Benchmarks
  - Establish baselines
- **Deliverable:** Performance regression detection

---

## Resource Estimate

| Action | Dev Days | QA Days | Total |
|--------|----------|---------|-------|
| Error Injection | 12 | 2 | 14 |
| Snapshot Refactor | 8 | 2 | 10 |
| ETMv4 Coverage | 4 | 1 | 5 |
| Comparative Tests | 3 | 1 | 4 |
| Benchmarks | 2 | 1 | 3 |
| **TOTAL** | **29** | **7** | **36** |

**Assuming 1 developer, 5-day weeks: 7-8 weeks**

---

## Success Metrics

After completing this plan:

| Metric | Before | Target | Success |
|--------|--------|--------|---------|
| Error test coverage | 5% | 60% | ✓ When error path hit % reaches 60% |
| Snapshot test quality | String comp | Semantic | ✓ When validators added to all 6 protocols |
| Go vs C++ known issues | Unknown | 0 | ✓ When comparative tests show parity |
| ETMv4 coverage | 62% | 75%+ | ✓ When tools report 75%+ |
| Failed/Skip tests | ~0 | 0 | ✓ When all actions complete with passing tests |

---

## Implementation Notes

### For Error Tests:
- Start with most critical protocols (ETMv4, PTM, STM)
- Use property-based testing patterns where possible
- Document why each error case matters for production

### For Snapshot Refactoring:
- Keep old string-comparison tests as fallback
- Make validators modular so other projects can reuse
- Add detailed error messages (helps debugging failures)

### For Comparative Tests:
- Assume C++ binary exists in CI environment
- Skip test gracefully if C++ binary unavailable
- Document setup requirements

### For ETMv4 Coverage:
- Don't aim for 100% coverage (some error paths are intentionally unreachable)
- Focus on high-impact code paths
- Prioritize state machine transitions

---

## Related Issues to Address

1. **Test Timeout Issues:** PTM/STM/ITM tests occasionally timeout
   - Investigate snapshot sizes
   - Consider test parallelization limits
   - Might need performance improvements

2. **Brittle Snapshot Tests:** Hard-coded snapshot paths
   - Consider snapshot registry/discovery mechanism
   - Allow dynamic snapshot test registration

3. **Duplicate Test Names:** ITM has "itm-decode-test" test name using "itm_only_raw" snapshot
   - Standardize naming: test_name should match primary snapshot
   - Document convention

