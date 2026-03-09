# ETE Decoder Analysis - CRITICAL FINDINGS SUMMARY

## Executive Summary

**Status**: 🔴 **GO IMPLEMENTATION CRITICALLY BROKEN**  
**Severity**: HIGH  
**Recommendation**: STOP - Fix before any production use

### Key Findings

1. **CRITICAL BUG**: Go decoder silently drops 6 ETE packet types
2. **DESIGN FLAW**: Test framework masks the bug by not checking output elements
3. **DATA LOSS**: ITE, transactional memory packets produce no output
4. **PARITY**: C++ implementation complete, Go is ~30% broken

---

## Root Cause Analysis

### The Bug

**File**: [opencsd/internal/etmv4/decoder.go:434-540](opencsd/internal/etmv4/decoder.go#L434-L540)

**Issue**: The packet dispatch switch statement in `decodePacket()` is missing handlers for 6 ETE packet types:

```
✅ HANDLED:  PktAsync, PktTraceInfo, PktAddrMatch, PktExcept, etc.
❌ MISSING:  ETE_PktITE, ETE_PktTransSt, ETE_PktTransCommit, 
            ETE_PktTSMarker, ETE_PktPeReset, ETE_PktTransFail
```

**Flow**:
```
Processor: ✅ Parses packets correctly
           ↓
Decoder: ❌ No case statement for ETE types
           ↓
Result: Packets silently dropped, no output elements
```

### Why Tests Pass

**File**: [opencsd/internal/ete/snapshot_test.go:391-393](opencsd/internal/ete/snapshot_test.go)

```go
func normalizeSnapshotLine(line string) string {
    if strings.Contains(line, "OCSD_GEN_TRC_ELEM_") {
        return ""  // ← STRIPS ALL OUTPUT ELEMENTS!
    }
}
```

Tests only compare **packet bytes**, not **output elements**. So:
- ✅ Packets parse without errors
- ✅ Tests pass
- ❌ **But output elements are never generated**

---

## Impact Assessment

### Affected Packet Types

| Packet | Type | Impact | Tests |
|--------|------|--------|-------|
| ITE (Instrumentation Trace Extension) | 0x09 | Software instrumentation data lost | ete-ite-instr ❌ |
| TRANS_ST (Transaction Start) | 0x0A | Transaction markers lost | tme_simple ❌ |
| TRANS_COMMIT | 0x0B | Transaction markers lost | tme_test ❌ |
| TS_MARKER (Timestamp) | 0x88 | Timestamp addressing lost | ts_marker ❌ |
| PE_RESET | 0x400 | Exception variants lost | ? |
| TRANS_FAIL | 0x401 | Transaction variants lost | ? |

### Existing Test Data That Exposes Bug

```
✅ ete-ite-instr.ppl         - 1 ITE packet that should generate output
✅ ete-ite-instr_multi_sess.ppl - Multiple ITE packets
✅ tme_simple.ppl            - 3 transactional packets
✅ tme_test.ppl              - 30+ transactional packets
✅ ts_marker.ppl             - Timestamp marker variants
```

Tests execute without errors but silently drop elements from these traces.

---

## Required Fixes

### Fix 1: Add Missing Hook Decoder Cases

**Location**: [decoder.go:434-540](opencsd/internal/etmv4/decoder.go#L434-L540)

**Add to the switch statement**:

```go
case ETE_PktITE:
    params := []uint32{
        uint32(pkt.ITEPkt.EL),
        uint32(pkt.ITEPkt.Value),
        uint32(pkt.ITEPkt.Value >> 32),
    }
    d.pushP0ElemParam(p0ITE, false, pkt.Type, d.IndexCurrPkt, params)

case ETE_PktTransSt:
    d.pushP0ElemParam(p0TransStart, d.config.CommTransP0(), pkt.Type, d.IndexCurrPkt, nil)
    if d.config.CommTransP0() {
        d.currSpecDepth++
    }

case ETE_PktTransCommit:
    d.pushP0ElemParam(p0TransCommit, false, pkt.Type, d.IndexCurrPkt, nil)

case ETE_PktTransFail:
    d.pushP0ElemParam(p0TransFail, false, pkt.Type, d.IndexCurrPkt, nil)

case ETE_PktTSMarker:
    // Timestamp marker variants - handled as address packets
    addr := pkt.VAddr
    d.lastIS = pkt.VAddrISA
    d.pushP0ElemAddr(pkt.Type, d.IndexCurrPkt, addr, d.lastIS, false)
    isAddr = true

case ETE_PktPeReset:
    // PE reset exception
    d.pushP0ElemExcept(pkt.Type, d.IndexCurrPkt, false, pkt.ExceptionInfo.ExceptionType)
    d.elemPendingAddr = false
```

**Time**: 30 minutes

### Fix 2: Enhance Test Framework (Optional but Recommended)

**Location**: [snapshot_test.go:391-393](opencsd/internal/ete/snapshot_test.go)

**Current Problem**: Test comparison ignores output elements

**Recommendation**: 
- Optionally enable full element validation with a test flag
- Create enhanced snapshot format that includes expected output elements
- Document that current tests only validate packet parsing

**Time**: 1-2 hours for full fix

---

## Verification Checklist

After implementing Fix 1:

- [ ] `go test ./internal/ete -v` - All tests should still pass
- [ ] Run decoder on real trace with ITE packets - should produce `GenElemSWIte` elements
- [ ] Run decoder on TME traces - should produce transaction elements in output
- [ ] Check output against golden files manually to verify element generation
- [ ] Re-enable full element comparison testing

---

## Comparison: C++ vs Go

### C++ Implementation
**Status**: ✅ **CORRECT**
- Config: Extends EtmV4Config
- Processor: Uses ETMv4 processor (TrcPktProcEtmV4I)
- Decoder: Uses ETMv4 decoder (TrcPktDecodeEtmV4I)
- ETE Feature Support: Implicit via ETMv4 infrastructure + version checks (MajVer >= 0x5)
- ITE Handling: [trc_pkt_decode_etmv4i.cpp:608-616](decoder/source/etmv4/trc_pkt_decode_etmv4i.cpp#L608-L616) ✅
- TRANS Handling: [trc_pkt_decode_etmv4i.cpp:584-602](decoder/source/etmv4/trc_pkt_decode_etmv4i.cpp#L584-L602) ✅

### Go Implementation
**Status**: 🔴 **BROKEN**
- Config: Extends etmv4.Config ✅
- Processor: Uses etmv4.Processor ✅
- Decoder: Uses etmv4.PktDecode ✅
- **BUT**: Decoder missing cases in switch statement ❌

---

## Timeline and Risk

### Implementation
- **Effort**: 1-2 hours (fix + testing)
- **Risk**: LOW - Isolated change, well-understood scope
- **Testing**: Existing tests validate no regression

### Deployment
- **Before Production**: Must fix - data loss is unacceptable
- **Severity**: CRITICAL
- **Workaround**: None - use C++ decoder for ETE traces with these features

---

## Responsible Areas

| Area | Owner | Status |
|------|-------|--------|
| C++ Decoder | ARM/Maintainer | ✅ Complete, no action |
| Go Decoder | Go implementer | 🔴 **BROKEN - ACTION REQUIRED** |
| Test Infrastructure | Test owner | ⚠️ Test design issue - consider enhancement |

---

## Additional Insights

### Why Go Implementation Diverged

The Go decoder was ported from C++ but the key difference is:
- **C++**: ETE features are **implicit** in ETMv4 decoder via version checks
- **Go**: ETE features require **explicit** case statements in decoder

The decoder.go `decodePacket()` function has cases for ETMv4 packets but calls them for **all** versions including ETE (MajVer >= 0x5). However, it's missing the ETE-specific cases.

### Why This Matters

This is not just a code completeness issue - it's a **data loss bug**:
1. User captures ETE trace with ITE/transactional data
2. Arms runs C++ decoder ✅ - gets full trace
3. User runs Go decoder ❌ - silent data loss
4. **Inconsistent results** between implementations

### How to Prevent in Future

1. Add version-gated tests that check for specific output elements
2. Make test comparison include trace elements, not just packets
3. Consider separate ETE decoder implementation if more divergence expected

---

## Conclusion

**The Go ETE decoder has a critical bug that causes silent data loss.**

All ITE, transactional memory, and some exception variants are parsed but never converted to output elements. The bug is masked by a test framework that doesn't validate output correctness.

**Recommendation**: Fix immediately before any production use of Go ETE decoder with ETE-specific features.

