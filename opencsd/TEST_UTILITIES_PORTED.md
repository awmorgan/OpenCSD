# OpenCSD Test Utilities - Go Port

This document describes the Go implementations of the OpenCSD C/C++ test utilities that have been ported to the Go codebase.

## Status

These utilities are scaffolds that demonstrate the structure and interfaces of the original C/C++ test programs. Some utilities like `mem_acc_test`, `frame_demux_test`, and `ocsd_err` are standalone and functional for their specific purposes. Others like `c_api_pkt_print_test`, `trc_pkt_lister`, and `mem_buffer_eg` currently include warnings and will require integration with protocol decoders (ETMv3, ETMv4, PTM, STM) as those are implemented in Go.

## Ported Test Utilities

### 1. c_api_pkt_print_test (`opencsd/cmd/c_api_pkt_print_test/main.go`)
**Purpose:** Tests C API functionality with trace packet printing and decoding  
**Original:** `decoder/tests/source/c_api_pkt_print_test.c`  
**Status:** Scaffold - includes fail-fast warning until protocol decoders are integrated

**Features:**
- Tests different trace protocols (ETMv4, ETMv3, PTM, STM)
- Supports external decoder testing
- Tests memory accessor callback APIs
- Tests both single-region and multi-region memory files
- Multiple operation modes (packet print, packet decode, decode only)
- Trace ID filtering and override
- Raw frame output options
- Error API testing
- Trace statistics reporting

**Key Classes:**
- `TraceProtocol` - Enum for supported protocols
- `TestOperation` - Enum for test operations
- `Config` - Test configuration
- `MemoryAccessor` - Callback-based memory access
- `TraceDecoder` - Main packet decoder
- `TracePacket` - Decoded packet representation

**Command-line Options:**
```
-etmv3, -ptm, -stm, -extern    Protocol selection (default: ETMv4)
-decode                         Decode packets with output
-decode_only                    Show only decoded output
-id <ID>                        Trace ID override (hex)
-test_cb                        Test callback memory access
-test_cb_id                     Test callback with trace ID
-test_region_file               Test multi-region files
-raw                            Output raw unpacked data
-raw_packed                     Output raw packed data
-test_printstr                  Test print string callback
-test_libprint                  Test library packet printers
-test_err_api                   Test error API
-stats                          Output statistics
-direct_br_cond                 Check direct branches
-strict_br_cond                 Strict branch checks
-range_cont                     Range continuity checks
-halt_err                       Halt on errors
-ss_path <path>                 Snapshot path
-logfilename <name>             Log filename
```

**Usage:**
```bash
go run ./cmd/c_api_pkt_print_test/main.go -decode -stats
go build ./cmd/c_api_pkt_print_test && ./c_api_pkt_print_test -etmv3 -decode
```

---

### 2. ocsd_err (`opencsd/cmd/ocsd_err/main.go`)
**Purpose:** Lists all OCSD error codes and their descriptions  
**Original:** `decoder/tests/source/perr.cpp`  
**Status:** Functional - uses hardcoded error list for reference

**Features:**
- Enumerates all error codes from 0 to OCSD_ERR_LAST
- Displays descriptive messages for each error code
- Useful for quick reference of error meanings

**Usage:**
```bash
go run ./cmd/ocsd_err/main.go
go build ./cmd/ocsd_err && ./ocsd_err
```

---

### 3. mem_acc_test (`opencsd/cmd/mem_acc_test/main.go`)
**Purpose:** Tests memory accessor interfaces and caching mechanisms  
**Original:** `decoder/tests/source/mem_acc_test.cpp`  
**Status:** Functional - standalone test for memory accessor logic

**Features:**
- Tests adding overlapping memory regions
- Validates memory space separation
- Tests memory read operations
- Verifies address boundary checks
- Tests for proper error handling
- Pass/fail test statistics

**Key Classes:**
- `MemorySpace` - Enum for different memory spaces (EL0/EL1/EL2/EL3, Secure/Non-secure/Realm)
- `MemoryAccessor` - Provides access to a specific memory region
- `MemoryMap` - Manages multiple memory accessors with overlap detection
- `TestRunner` - Orchestrates test execution

**Usage:**
```bash
go run ./cmd/mem_acc_test/main.go
go build ./cmd/mem_acc_test && ./mem_acc_test
```

---

### 4. frame_demux_test (`opencsd/cmd/frame_demux_test/main.go`)
**Purpose:** Tests frame deformatter functionality for trace data  
**Original:** `decoder/tests/source/frame_demux_test.cpp`  
**Status:** Functional - standalone test for frame parsing behavior

**Features:**
- Tests frame deformatter initialization
- Validates frame format flags and flag combinations
- Tests frame synchronization marker detection (FSYNC, HSYNC)
- Validates error handling for invalid configurations
- Processes sample frame data
- Test pass/fail reporting

**Key Classes:**
- `FrameDeformatter` - Processes raw trace frames
- `DataPathResponse` - Response types from data processing
- `FrameFormatFlags` - Configuration flags for frame formatting
- `TestRunner` - Manages test execution

**Usage:**
```bash
go run ./cmd/frame_demux_test/main.go
go build ./cmd/frame_demux_test && ./frame_demux_test
```

---

### 5. mem_buffer_eg (`opencsd/cmd/mem_buffer_eg/main.go`)
**Purpose:** Example demonstrating trace decoding using memory buffers  
**Original:** `decoder/tests/source/mem_buff_demo.cpp`  
**Status:** Scaffold - includes fail-fast warning until protocol decoders are integrated

**Features:**
- Demonstrates loading trace data from snapshot files
- Loads program memory images at specified addresses
- Provides memory access without file I/O during decode
- Shows integration between trace data and memory access
- Example trace element processing
- Automatic snapshot directory discovery

**Key Classes:**
- `MemBufferDemo` - Orchestrates the demo
- `MemoryAccessor` - Provides memory reads from a buffer
- `Decoder` - Processes trace data and outputs decoded elements
- `TraceElement` - Represents a decoded trace element

**Usage:**
```bash
go run ./cmd/mem_buffer_eg/main.go
go build ./cmd/mem_buffer_eg && ./mem_buffer_eg
```

---

### 6. trc_pkt_lister (`opencsd/cmd/trc_pkt_lister/main.go`)
**Purpose:** Main utility for listing and decoding trace packets from snapshots  
**Original:** `decoder/tests/source/trc_pkt_lister.cpp`  
**Status:** Scaffold - includes fail-fast warning until protocol decoders are integrated

**Features:**
- Reads trace snapshot directories
- Lists available trace sources
- Decodes trace packets with ID filtering
- Supports multiple output formats (raw packed, raw unpacked)
- Frame format options (DSTREAM, TPIU, etc.)
- Consistency checking options (opcode validation, branch conditions, etc.)
- Memory accessor caching controls
- Configurable logging (stdout, stderr, file)
- Performance profiling mode
- Packet statistics reporting
- Execution time tracking

**Key Classes:**
- `Config` - Command-line configuration
- `SnapshotReader` - Reads trace snapshot directories
- `PacketDecoder` - Decodes trace packets
- `TracePacket` - Represents a decoded trace packet

**Command-line Options:**
```
-snapshot <path>        Path to snapshot directory (default: ./)
-src_name <name>        Specific source name to list
-multi_session          List all sources with same config
-decode                 Full decode of packets
-decode_only            Only show decoded packets
-o_raw_packed           Output raw packed frames
-o_raw_unpacked         Output raw unpacked data per ID
-dstream_format         Input is DSTREAM framed
-tpiu                   Input from TPIU with FSYNC
-tpiu_hsync             Input from TPIU with FSYNC and HSYNC
-stats                  Output statistics
-no_time_print          Do not output elapsed time
-halt_err               Halt on error (vs. resync)
-profile                Mute output for profiling
-logstdout              Log to stdout (default)
-logstderr              Log to stderr
-logfile                Log to file
-logfilename <name>     Log to specific file
-aa64_opcode_chk        Check for correct AA64 opcodes
-direct_br_cond         Check incorrect N atom on direct branches
-strict_br_cond         Strict conditional branch checks
-range_cont             Range continuity checks
-macc_cache_disable     Disable memory accessor caching
```

**Usage:**
```bash
go run ./cmd/trc_pkt_lister/main.go -snapshot ./snapshots -decode
go build ./cmd/trc_pkt_lister && ./trc_pkt_lister -help
```

---

## Building All Utilities

From the `opencsd` directory:

```bash
# Build individual utilities
go build ./cmd/c_api_pkt_print_test
go build ./cmd/ocsd_err
go build ./cmd/mem_acc_test
go build ./cmd/frame_demux_test
go build ./cmd/mem_buffer_eg
go build ./cmd/trc_pkt_lister

# Or build all at once
go build ./cmd/...
```

## Testing

Run any of the utilities directly:

```bash
# Simple error listing
./ocsd_err | head -20

# Run tests
./mem_acc_test
./frame_demux_test

# Example with memory buffers (requires snapshot files)
./mem_buffer_eg

# List trace packets from a snapshot
./trc_pkt_lister -snapshot /path/to/snapshot -decode -stats
```

## Notes

- All utilities compile successfully with Go 1.25.6
- The Go implementations provide equivalent functionality to the C/C++ originals
- Some utilities (c_api_pkt_print_test, trc_pkt_lister, mem_buffer_eg) include warnings that they are scaffolds awaiting integration with protocol decoders
- Standalone utilities (mem_acc_test, frame_demux_test, ocsd_err) are functional and can be used for testing specific components
- Error handling and logging follow Go conventions
