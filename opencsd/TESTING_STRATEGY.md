# Go Port Testing Strategy

## Overview

This document explains how to verify the Go implementation of OpenCSD against the existing C++ codebase using TDD with the original test data.

## C++ Test Infrastructure

### Test Data Structure
```
decoder/tests/
├── snapshots/           # Binary trace data + configuration
│   ├── trace_cov_a15/  # PTM test (PTM_0_2.bin)
│   ├── TC2/            # Multi-protocol (PTM IDs 0x13, 0x14)
│   └── tc2-ptm-rstk-t32/ # PTM return stack test
├── results/            # Reference output in .ppl format
│   ├── trace_cov_a15.ppl
│   ├── TC2.ppl
│   └── tc2-ptm-rstk-t32.ppl
└── run_pkt_decode_tests.bash  # Main test runner
```

### Snapshot Structure
Each snapshot directory contains:
- **Binary trace files**: `PTM_0_2.bin`, `ETM_0_4.bin`, etc.
- **trace.ini**: Metadata (trace sources, buffer mappings, core assignments)
- **Memory dumps**: `mem_*.bin` files (for decode tests)
- **snapshot.ini**: Decoder configuration (register values, protocol settings)

### .ppl Output Format
The Packet Print List (.ppl) format shows:
```
Idx:<byte_offset>; ID:<trace_id>; [<hex_bytes>]; <packet_type> : <description>; 
Idx:<byte_offset>; ID:<trace_id>; OCSD_GEN_TRC_ELEM_<element_type>(<details>)
```

**Example PTM output:**
```
Idx:26565; ID:13; [0x00 0x00 0x00 0x00 0x00 0x80 ];	ASYNC : Alignment Synchronisation Packet; 
Idx:26571; ID:13; [0x08 0x83 0x8d 0x01 0xc0 0x01 ];	ISYNC : Instruction Synchronisation packet; (Periodic); Addr=0xc0018d82; S;  ISA=Thumb2; 
Idx:26571; ID:13; OCSD_GEN_TRC_ELEM_TRACE_ON( [begin or filter])
Idx:26571; ID:13; OCSD_GEN_TRC_ELEM_PE_CONTEXT((ISA=T32) S; 32-bit; )
Idx:26579; ID:13; [0x42 0xcc 0x97 0xc6 0xce 0xaf 0x90 0x80 0x80 0x00 0x00 ];	TIMESTAMP : Timestamp packet; TS=0x00000082F9D18BCC ~[0x82F9D18BCC](562537008076); Cycles=0; 
Idx:26590; ID:13; [0xe8 0x20 ];	ATOM : Atom packet; E; Cycles=522; 
```

## TDD Strategy for Go Port

### Phase 1: Packet-Level Validation (Current)

**Objective**: Parse raw trace bytes into packets matching C++ output

**Test Approach**:
1. Use same binary snapshot files as input
2. Generate .ppl-compatible output from Go decoder
3. Compare packet boundaries, types, and hex dumps

**Implementation**:
```go
// opencsd/ptm/decoder_test.go
func TestPTMPackets_TraceA15(t *testing.T) {
    // Read binary trace
    raw, _ := os.ReadFile("../decoder/tests/snapshots/trace_cov_a15/PTM_0_2.bin")
    
    // Parse with Go decoder
    decoder := ptm.NewDecoder(0) // Trace ID 0
    packets, _ := decoder.Parse(raw)
    
    // Generate .ppl format output
    output := GeneratePPL(packets)
    
    // Compare against reference
    reference, _ := os.ReadFile("../decoder/tests/results/trace_cov_a15.ppl")
    
    // Extract packet lines (Idx: ID: [...])
    gotPkts := ExtractPacketLines(output)
    wantPkts := ExtractPacketLines(string(reference))
    
    if !reflect.DeepEqual(gotPkts, wantPkts) {
        t.Errorf("Packet mismatch\nGot:\n%s\nWant:\n%s", 
                 gotPkts[0:10], wantPkts[0:10])
    }
}
```

**Key Validation Points**:
- Byte offset (`Idx:`) matches exactly
- Trace ID (`ID:`) correct
- Hex byte sequence matches
- Packet type identification correct
- Multi-byte packet boundaries accurate

### Phase 2: Semantic Validation

**Objective**: Verify packet interpretation (addresses, cycle counts, etc.)

**Test Approach**:
```go
func TestPTMPacketDecoding_ASYNC(t *testing.T) {
    raw := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
    
    pkt, _ := ptm.ParsePacket(raw)
    
    assert.Equal(t, ptm.PacketTypeASYNC, pkt.Type)
    assert.Equal(t, 6, pkt.Size)
}

func TestPTMPacketDecoding_ISYNC(t *testing.T) {
    raw := []byte{0x08, 0x83, 0x8d, 0x01, 0xc0, 0x01}
    
    pkt, _ := ptm.ParsePacket(raw)
    
    assert.Equal(t, ptm.PacketTypeISYNC, pkt.Type)
    assert.Equal(t, uint64(0xc0018d82), pkt.Address)
    assert.True(t, pkt.SecureState)
    assert.Equal(t, ptm.ISAThumb2, pkt.ISA)
}
```

### Phase 3: Integration Testing

**Objective**: Full pipeline validation with C++ test runner

**Approach**: Create a Go test program that mimics `trc_pkt_lister`:

```bash
# opencsd/cmd/pkt_lister/main.go
go run ./cmd/pkt_lister -ss_dir ../decoder/tests/snapshots/trace_cov_a15 \
                         -protocol ptm \
                         -trace_id 0 \
                         -logfilename ./test_output.ppl
```

Then diff against C++ output:
```bash
# Compare packet lines only (ignore library version, paths, etc.)
grep "^Idx:" ../decoder/tests/results/trace_cov_a15.ppl > cpp_packets.txt
grep "^Idx:" test_output.ppl > go_packets.txt
diff cpp_packets.txt go_packets.txt
```

## Leveraging C++ Tests for Behavior Validation

### Option 1: Modified C++ Test with JSON Output

Create a modified `trc_pkt_lister` that outputs JSON for easier comparison:

```c
// decoder/tests/source/json_pkt_printer.c
void print_packet_json(const ocsd_pkt *pkt, uint64_t idx) {
    printf("{\"idx\":%llu,\"id\":%u,\"bytes\":[", idx, pkt->trace_id);
    for (int i = 0; i < pkt->size; i++) {
        printf("%s0x%02x", i > 0 ? "," : "", pkt->data[i]);
    }
    printf("],\"type\":\"%s\"}\n", packet_type_name(pkt->type));
}
```

Build and run:
```bash
cd decoder/build/mingw
mingw32-make json_pkt_lister
../../tests/bin/mingw64/rel/json_pkt_lister -ss_dir ../../tests/snapshots/trace_cov_a15 > ptm_reference.json
```

Use in Go tests:
```go
func TestAgainstCppReference(t *testing.T) {
    var cppPackets []CppPacket
    json.Unmarshal([]byte(referenceJSON), &cppPackets)
    
    // Parse with Go
    goPackets := ptm.Parse(rawData)
    
    // Compare
    for i, cpp := range cppPackets {
        assert.Equal(t, cpp.Bytes, goPackets[i].RawBytes)
        assert.Equal(t, cpp.Type, goPackets[i].Type.String())
    }
}
```

### Option 2: Shared Test Data as Go Embed

Embed C++ test expectations directly:

```go
//go:embed testdata/ptm_reference.json
var ptmReferenceJSON string

func TestPTMDecoder(t *testing.T) {
    type TestCase struct {
        Name      string
        Input     string // hex string
        Expected  []Packet
    }
    
    var cases []TestCase
    json.Unmarshal([]byte(ptmReferenceJSON), &cases)
    
    for _, tc := range cases {
        t.Run(tc.Name, func(t *testing.T) {
            input := hexDecode(tc.Input)
            got := decoder.Parse(input)
            assert.Equal(t, tc.Expected, got)
        })
    }
}
```

### Option 3: Cross-Validation Test Script

Create a Bash script that runs both decoders and compares:

```bash
#!/bin/bash
# opencsd/scripts/validate_go.sh

SNAPSHOT="$1"
CPP_BIN="../decoder/tests/bin/mingw64/rel/trc_pkt_lister"
GO_BIN="./bin/pkt_lister"

# Run C++ decoder
$CPP_BIN -ss_dir "../decoder/tests/snapshots/$SNAPSHOT" \
         -no_time_print -logfilename cpp_output.ppl

# Run Go decoder  
$GO_BIN -ss_dir "../decoder/tests/snapshots/$SNAPSHOT" \
        -logfilename go_output.ppl

# Extract and compare packet data
grep "^Idx:" cpp_output.ppl | sort > cpp_packets.txt
grep "^Idx:" go_output.ppl | sort > go_packets.txt

if diff -u cpp_packets.txt go_packets.txt; then
    echo "✓ $SNAPSHOT: Go and C++ outputs match"
    exit 0
else
    echo "✗ $SNAPSHOT: Outputs differ"
    exit 1
fi
```

Run validation:
```bash
./scripts/validate_go.sh trace_cov_a15
./scripts/validate_go.sh TC2
./scripts/validate_go.sh tc2-ptm-rstk-t32
```

## Recommended TDD Workflow

### Step 1: Write Failing Test
```go
func TestPTMSync_FirstPacket(t *testing.T) {
    raw := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}
    
    decoder := ptm.NewDecoder(0)
    packets, _ := decoder.Parse(raw)
    
    require.Len(t, packets, 1)
    assert.Equal(t, ptm.PacketTypeASYNC, packets[0].Type)
}
```

Run: `go test ./ptm -run TestPTMSync_FirstPacket -v`

### Step 2: Implement Minimal Code
```go
// opencsd/ptm/decoder.go
func (d *Decoder) Parse(raw []byte) ([]Packet, error) {
    if bytes.HasPrefix(raw, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80}) {
        return []Packet{{
            Type: PacketTypeASYNC,
            Size: 6,
            Data: raw[0:6],
        }}, nil
    }
    return nil, fmt.Errorf("unknown packet")
}
```

### Step 3: Validate Against C++ Output
```bash
# Generate reference from C++ for this specific test case
echo "00 00 00 00 00 80" | xxd -r -p > /tmp/test.bin
../decoder/tests/bin/mingw64/rel/trc_pkt_lister \
    -raw_file /tmp/test.bin -protocol ptm -trace_id 0 \
    | grep "^Idx:"

# Expected output:
# Idx:0; ID:0; [0x00 0x00 0x00 0x00 0x00 0x80 ];	ASYNC : Alignment Synchronisation Packet;
```

### Step 4: Expand Test Coverage
```go
func TestPTMSync_MultiplePackets(t *testing.T) {
    // ASYNC + ISYNC from trace_cov_a15.ppl
    raw := hexDecode("00 00 00 00 00 80 08 58 05 00 80 61")
    
    packets, _ := ptm.Parse(raw)
    
    require.Len(t, packets, 2)
    assert.Equal(t, ptm.PacketTypeASYNC, packets[0].Type)
    assert.Equal(t, ptm.PacketTypeISYNC, packets[1].Type)
    assert.Equal(t, uint64(0x80000558), packets[1].Address)
}
```

### Step 5: Full Snapshot Validation
```go
func TestPTM_FullSnapshot_TraceA15(t *testing.T) {
    raw, _ := os.ReadFile("../decoder/tests/snapshots/trace_cov_a15/PTM_0_2.bin")
    
    decoder := ptm.NewDecoder(0)
    packets, err := decoder.Parse(raw)
    require.NoError(t, err)
    
    // Load C++ reference
    ref := loadCppReference(t, "trace_cov_a15.ppl", 0)
    
    require.Equal(t, len(ref), len(packets), "packet count mismatch")
    
    for i, want := range ref {
        got := packets[i]
        assert.Equal(t, want.ByteOffset, got.Offset, "Idx mismatch at packet %d", i)
        assert.Equal(t, want.Bytes, got.RawBytes, "Bytes mismatch at packet %d", i)
        assert.Equal(t, want.Type, got.Type.String(), "Type mismatch at packet %d", i)
    }
}
```

## Continuous Integration

Add GitHub Actions workflow:

```yaml
# .github/workflows/validate-go.yml
name: Validate Go Port

on: [push, pull_request]

jobs:
  cross-validate:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      
      - name: Build C++ decoders
        run: |
          cd decoder/build/mingw
          mingw32-make
      
      - name: Build Go decoders  
        run: |
          cd opencsd
          go build ./...
      
      - name: Run cross-validation
        run: |
          cd opencsd
          ./scripts/validate_go.sh trace_cov_a15
          ./scripts/validate_go.sh TC2
```

## Summary

**Best Practices**:
1. ✅ Use same binary snapshots for both C++ and Go
2. ✅ Parse C++ .ppl output as ground truth
3. ✅ Start with packet-level validation (byte boundaries)
4. ✅ Progress to semantic validation (field extraction)
5. ✅ Automate cross-validation in CI
6. ✅ Keep TDD loop tight: test → implement → validate

**Quick Start**:
```bash
# 1. Run C++ tests to generate reference
cd decoder/tests
./run_pkt_decode_tests.bash -bindir ./bin/mingw64/rel/

# 2. Implement Go decoder with TDD
cd ../../opencsd/ptm
go test -v

# 3. Cross-validate
cd ..
./scripts/validate_go.sh trace_cov_a15
```
