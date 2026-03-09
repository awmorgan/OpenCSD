# OpenCSD C++ Decoder Implementation - Comprehensive Architecture Overview

## Executive Summary

OpenCSD implements a sophisticated, layered trace decoder architecture supporting multiple ARM CoreSight protocols. The design follows a component-based pattern with clear separation of concerns across three processing layers: frame deformatting, packet processing, and packet decoding. All components share a common infrastructure for error handling, component management, and data flow control.

---

## 1. MAIN ARCHITECTURE AND DECODER ORGANIZATION

### 1.1 Overview

The OpenCSD decoder architecture follows a **pipeline-based component architecture** with three primary processing layers:

```
Input Data Stream
       ↓
[Frame Deformatter] - Demultiplexes CoreSight frames by trace source ID (CSID)
       ↓ (per CSID)
[Packet Processor] - Converts raw bytes to protocol-specific packets
       ↓
[Packet Decoder] - Converts packets to generic trace elements
       ↓
[Output Analysis Module] - Consumes generic trace elements
```

### 1.2 Decode Tree - The Root Component

**Class:** `DecodeTree` ([decoder/include/common/ocsd_dcd_tree.h](decoder/include/common/ocsd_dcd_tree.h))

The DecodeTree is the primary API entry point for creating a multi-source trace decode infrastructure:

- **Factory Method:** `DecodeTree::CreateDecodeTree(src_type, formatterCfgFlags)`
- **Responsibilities:**
  - Creates and manages frame deformatter(s) as needed
  - Maintains a list of decode tree elements (individual decoders)
  - Provides default error logging infrastructure
  - Supports multiple trace sources in single capture buffer
  - Acts as ITrcDataIn for receiving raw trace data

### 1.3 Component Structure

The decoder system is organized into **vertical stacks per protocol**, with **horizontal layers** of base classes:

#### Horizontal Layer Pattern

Each protocol implementation follows this structure:

| Layer | Role | Base Class | Pattern |
|-------|------|-----------|---------|
| **Input** | Raw bytes by CSID | ITrcDataIn | Frame deformatter output |
| **Packet Processing** | Bytes → Protocol Packets | TrcPktProcBase | trc_pkt_proc_*.cpp |
| **Packet Decoding** | Protocols → Generic Elements | TrcPktDecodeBase | trc_pkt_decode_*.cpp |
| **Output** | Generic Element Consumer | ITrcGenElemIn | Analysis tool |

#### Vertical Stack Pattern

Each protocol implements:
```
{protocol}/
  ├── Packet Types       (trc_pkt_types_*.h)
  ├── Configuration      (trc_cmp_cfg_*.h)
  ├── Packet Processor   (trc_pkt_proc_*.h/cpp)
  ├── Packet Elements    (trc_pkt_elem_*.h/cpp)
  ├── Packet Decoder     (trc_pkt_decode_*.h/cpp)
  └── Decoder Manager    (trc_dcd_mngr_*.h)
```

---

## 2. KEY FILES AND CLASSES FOR EACH PROTOCOL

### 2.1 ETMv4 (Embedded Trace Macrocell v4)

**Location:** `decoder/{include,source}/opencsd/etmv4/` and `decoder/{include,source}/etmv4/`

| File | Class | Purpose |
|------|-------|---------|
| `trc_pkt_types_etmv4.h` | `ocsd_etmv4_i_pkt_type` enum | I-stream packet type definitions (TRACE_INFO, TIMESTAMP, EXCEPT, CONDRES, ATOM, etc.) |
| `trc_cmp_cfg_etmv4.h` | `EtmV4Config` | Configuration class for ETMv4 component |
| `trc_pkt_proc_etmv4i.h/cpp` | `TrcPktProcEtmV4I` | Converts ETMv4 bytes to EtmV4ITrcPacket |
| `trc_pkt_elem_etmv4i.h/cpp` | `EtmV4ITrcPacket` | ETMv4 I-stream packet element structure |
| `trc_pkt_decode_etmv4i.h/cpp` | `TrcPktDecodeEtmV4I` | Decodes EtmV4ITrcPacket to OcsdTraceElement |
| `trc_dcd_mngr_etmv4i.h/cpp` | `DecoderMgrEtmV4I` | Manager/factory for ETMv4 decoder instances |
| `etmv4_decoder.h` | - | Convenience include for all ETMv4 components |

**Key Features:**
- Support for instruction trace atoms (E/N patterns)
- Exception and exception return handling
- Timestamp and cycle count packets
- Speculative execution (commit/cancel/mispredict)
- Data synchronization markers
- Full conditional instruction tracing
- VMSpace-aware execution tracking

**Key Methods in Decoder:**
- `processAtom()` - Handle single instruction atoms
- `processQElement()` - Handle Q (N-instruction) elements
- `processSourceAddress()` - Handle address sync packets
- `processException()` - Handle exception packets
- `resolveElements()` - Commit/cancel speculation stack

### 2.2 ETMv3 (Embedded Trace Macrocell v3)

**Location:** `decoder/{include,source}/opencsd/etmv3/` and `decoder/{include,source}/etmv3/`

| File | Class | Purpose |
|------|-------|---------|
| `trc_pkt_types_etmv3.h` | `ocsd_etmv3_pkt_type` enum | Packet types (SYNC, ATOM, ADDR, EXCEPT, etc.) |
| `trc_cmp_cfg_etmv3.h` | `EtmV3Config` | ETMv3 configuration |
| `trc_pkt_proc_etmv3.h/cpp` | `TrcPktProcEtmV3` | Packet processor |
| `trc_pkt_elem_etmv3.h/cpp` | `EtmV3TrcPacket` | Packet element |
| `trc_pkt_decode_etmv3.h/cpp` | `TrcPktDecodeEtmV3` | Packet decoder |
| `trc_pkt_proc_etmv3_impl.h/cpp` | - | Implementation details for processor |
| `trc_dcd_mngr_etmv3.h/cpp` | `DecoderMgrEtmV3` | Decoder manager |

**Key Differences from ETMv4:**
- Simpler atom format (single instruction per atom)
- No speculation state (all atoms committed)
- Simpler configuration model
- Legacy protocol support

### 2.3 PTM (Program Trace Macrocell)

**Location:** `decoder/{include,source}/opencsd/ptm/` and `decoder/{include,source}/ptm/`

| File | Class | Purpose |
|------|-------|---------|
| `trc_pkt_types_ptm.h` | `ocsd_ptm_pkt_type` enum | PTM packet types |
| `trc_cmp_cfg_ptm.h` | `PtmConfig` | PTM configuration |
| `trc_pkt_proc_ptm.h/cpp` | `TrcPktProcPTM` | Packet processor |
| `trc_pkt_elem_ptm.h/cpp` | `PtmTrcPacket` | Packet element |
| `trc_pkt_decode_ptm.h/cpp` | `TrcPktDecodePTM` | Packet decoder |
| `trc_dcd_mngr_ptm.h/cpp` | `DecoderMgrPTM` | Decoder manager |
| `ptm_decoder.h` | - | Convenience include |

**Key Features:**
- Simpler core instruction trace than ETMv4/v3
- Supports Thumb and ARM instruction sets
- Basic exception tracing
- Cycle counting

### 2.4 STM (Software Trace Macrocell)

**Location:** `decoder/{include,source}/opencsd/stm/` and `decoder/{include,source}/stm/`

| File | Class | Purpose |
|------|-------|---------|
| `trc_pkt_types_stm.h` | `ocsd_stm_pkt_type` enum | STM packet types (ASYNC, MASTER, CHANNEL, DATA, FLAG, etc.) |
| `trc_cmp_cfg_stm.h` | `StmConfig` | STM configuration |
| `trc_pkt_proc_stm.h/cpp` | `TrcPktProcSTM` | Packet processor |
| `trc_pkt_elem_stm.h/cpp` | `StmTrcPacket` | Packet element |
| `trc_pkt_decode_stm.h/cpp` | `TrcPktDecodeSTM` | Packet decoder |
| `trc_dcd_mngr_stm.h/cpp` | `DecoderMgrSTM` | Decoder manager |
| `stm_decoder.h` | - | Convenience include |

**Key Features:**
- Software-generated trace (not hardware)
- Master/channel model for event organization
- Variably-sized data payloads (4/8/16/32/64-bit)
- Flag packets for markers
- Error and trigger packets

### 2.5 ITM (Instrumentation Trace Macrocell)

**Location:** `decoder/{include,source}/opencsd/itm/` and `decoder/{include,source}/itm/`

| File | Class | Purpose |
|------|-------|---------|
| `trc_pkt_types_itm.h` | `ocsd_itm_pkt_type` enum | ITM packet types |
| `trc_cmp_cfg_itm.h` | `ItmConfig` | ITM configuration |
| `trc_pkt_proc_itm.h/cpp` | `TrcPktProcITM` | Packet processor |
| `trc_pkt_elem_itm.h/cpp` | `ItmTrcPacket` | Packet element |
| `trc_pkt_decode_itm.h/cpp` | `TrcPktDecodeITM` | Packet decoder |
| `trc_dcd_mngr_itm.h/cpp` | `DecoderMgrITM` | Decoder manager |
| `itm_decoder.h` | - | Convenience include |

**Key Features:**
- ARM M-series microcontroller tracing
- Similar to STM but M-profile specific
- Software-generated stimulus packets
- Variably-sized data

### 2.6 ETE (Embedded Trace Extension)

**Location:** `decoder/{include,source}/opencsd/ete/` and `decoder/{include,source}/ete/`

| File | Class | Purpose |
|------|-------|---------|
| `trc_pkt_types_ete.h` | `ocsd_ete_pkt_type` enum | ETE packet types |
| `trc_cmp_cfg_ete.h` | `EteConfig` | ETE configuration |
| `trc_dcd_mngr_ete.h/cpp` | `DecoderMgrETE` | Decoder manager |
| `ete_decoder.h` | - | Convenience include |

**Key Features:**
- Latest ARM trace extension
- Enhanced instruction tracing
- Extended timestamp formats
- Compatible with ETMv4 base structure

---

## 3. FRAME DEFORMATTER AND PACKET PROCESSING INFRASTRUCTURE

### 3.1 Frame Deformatter

**Class:** `TraceFormatterFrameDecoder` ([decoder/include/common/trc_frame_deformatter.h](decoder/include/common/trc_frame_deformatter.h))

**Purpose:** Converts CoreSight formatted trace frames into per-CSID data streams.

**Key Methods:**
```cpp
ocsd_datapath_resp_t TraceDataIn(
    const ocsd_datapath_op_t op,
    const ocsd_trc_index_t index,
    const uint32_t dataBlockSize,
    const uint8_t *pDataBlock,
    uint32_t *numBytesProcessed);

componentAttachPt<ITrcDataIn> *getIDStreamAttachPt(uint8_t ID);
ocsd_err_t Configure(uint32_t cfg_flags);
ocsd_err_t OutputFilterIDs(std::vector<uint8_t> &id_list, bool bEnable);
```

**Architecture:**
- Accepts raw CoreSight frame data
- Extracts CSID from each frame/packet
- Routes demultiplexed data to per-CSID packet processors
- Tracks frame synchronization markers (if enabled)

### 3.2 Packet Processor Base Classes

**Base Interface:** `TrcPktProcI` ([decoder/include/common/trc_pkt_proc_base.h](decoder/include/common/trc_pkt_proc_base.h))

Defines virtual methods each protocol processor must implement:
```cpp
virtual ocsd_datapath_resp_t processData(
    const ocsd_trc_index_t index,
    const uint32_t dataBlockSize,
    const uint8_t *pDataBlock,
    uint32_t *numBytesProcessed) = 0;

virtual ocsd_datapath_resp_t onEOT() = 0;
virtual ocsd_datapath_resp_t onReset() = 0;
virtual ocsd_datapath_resp_t onFlush() = 0;
virtual ocsd_err_t onProtocolConfig() = 0;
virtual const bool isBadPacket() const = 0;
```

**Template Base:** `TrcPktProcBase<P, Pt, Pc>`
- **P:** Packet class (e.g., `EtmV4ITrcPacket`)
- **Pt:** Packet type class (e.g., `ocsd_etmv4_i_pkt_type`)
- **Pc:** Packet configuration (e.g., `EtmV4Config`)

**Provides:**
- Byte buffer management
- Packet extraction and state machine
- Attachment points for packet output
- Common data path operation handling

### 3.3 Data Flow Control

**Response Codes:**
| Code | Meaning | Action |
|------|---------|--------|
| `OCSD_DATAPATH_OK` | Data processed successfully | Continue input |
| `OCSD_DATAPATH_WAIT` | Downstream full, can't process | Pause input, retry |
| `OCSD_DATAPATH_EOS` | End of stream | Flush pending data |

**Operation Types:**
| Operation | Purpose | Effect |
|-----------|---------|--------|
| `OCSD_OP_DATA` | Process data block | Decode and output |
| `OCSD_OP_EOT` | End of trace | Flush incomplete packets |
| `OCSD_OP_RESET` | Reset decoder | Clear state, drop pending |
| `OCSD_OP_FLUSH` | Flush buffers | Output all pending data |

---

## 4. COMMON INTERFACES AND BASE CLASSES

### 4.1 Core Data Flow Interfaces

#### ITrcDataIn - Raw Byte Input
```cpp
virtual ocsd_datapath_resp_t TraceDataIn(
    const ocsd_datapath_op_t op,
    const ocsd_trc_index_t index,
    const uint32_t dataBlockSize,
    const uint8_t *pDataBlock,
    uint32_t *numBytesProcessed) = 0;
```
- Used by: Frame deformatter (input), packet processors (input)
- Provides: Raw byte stream consumption with flow control

#### IPktDataIn<P> - Protocol Packet Input
```cpp
virtual ocsd_datapath_resp_t PacketDataIn(
    const ocsd_datapath_op_t op,
    const ocsd_trc_index_t index_sop,
    const P *p_packet_in) = 0;
```
- Used by: Packet decoders
- Provides: Protocol-specific packet consumption
- Benefits: Type safety via templates

#### ITrcGenElemIn - Generic Element Output
```cpp
virtual ocsd_datapath_resp_t TraceElemIn(
    const ocsd_trc_index_t index_sop,
    const uint8_t trc_chan_id,
    const OcsdTraceElement &elem) = 0;
```
- Used by: Analysis modules, test harnesses
- Provides: Final trace element consumption
- Universal output format across all protocols

### 4.2 Decoder Manager Interface

**Class:** `IDecoderMngr` ([decoder/include/common/ocsd_dcd_mngr_i.h](decoder/include/common/ocsd_dcd_mngr_i.h))

Factory and attachment interface for decoders:

```cpp
// Factory methods
virtual ocsd_err_t createDecoder(
    const int create_flags,
    const int instID,
    const CSConfig *p_config,
    TraceComponent **ppComponent) = 0;

virtual ocsd_err_t destroyDecoder(TraceComponent *pComponent) = 0;

// Attachment methods
virtual ocsd_err_t attachErrorLogger(
    TraceComponent *pComponent,
    ITraceErrorLog *pIErrorLog) = 0;

virtual ocsd_err_t attachInstrDecoder(
    TraceComponent *pComponent,
    IInstrDecode *pIInstrDec) = 0;

virtual ocsd_err_t attachMemAccessor(
    TraceComponent *pComponent,
    ITargetMemAccess *pMemAccessor) = 0;

virtual ocsd_err_t attachOutputSink(
    TraceComponent *pComponent,
    ITrcGenElemIn *pOutSink) = 0;

// Configuration
virtual ocsd_err_t createConfigFromDataStruct(
    CSConfig **pConfigBase,
    const void *pDataStruct) = 0;
```

### 4.3 TraceComponent - Universal Base

**Class:** `TraceComponent` ([decoder/include/common/trc_component.h](decoder/include/common/trc_component.h))

Base class for all decoder components:

**Features:**
- Error logger attachment point
- Operational mode flags (protocol-specific)
- Component naming and instance ID
- Error message logging
- Association with paired components (e.g., pkt proc ↔ pkt decoder)

**Key Methods:**
```cpp
componentAttachPt<ITraceErrorLog> *getErrorLogAttachPt();
void LogError(const ocsdError &Error);
void LogMessage(const ocsd_err_severity_t filter_level, const std::string &msg);
ocsd_err_t setComponentOpMode(uint32_t op_flags);
```

### 4.4 Packet Decoder Base

**Class:** `TrcPktDecodeI` ([decoder/include/common/trc_pkt_decode_base.h](decoder/include/common/trc_pkt_decode_base.h))

Base interface for all packet decoders:

**Virtual Methods:**
```cpp
virtual ocsd_datapath_resp_t processPacket() = 0;
virtual ocsd_datapath_resp_t onEOT() = 0;
virtual ocsd_datapath_resp_t onReset() = 0;
virtual ocsd_datapath_resp_t onFlush() = 0;
virtual ocsd_err_t onProtocolConfig() = 0;
virtual const uint8_t getCoreSightTraceID() = 0;
```

**Attachment Points:**
- Trace element output (ITrcGenElemIn)
- Memory access (ITargetMemAccess) - optional
- Instruction decode (IInstrDecode) - optional

**Features:**
- Initialization checking (checkInit())
- Optional memory and instruction decode dependencies
- Output element methods with automatic indexing

---

## 5. ERROR HANDLING AND LOGGING MECHANISMS

### 5.1 Error Object

**Class:** `ocsdError` ([decoder/include/common/ocsd_error.h](decoder/include/common/ocsd_error.h))

Comprehensive error representation:

**Constructors (multiple overloads):**
```cpp
ocsdError(const ocsd_err_severity_t sev_type, const ocsd_err_t code);
ocsdError(const ocsd_err_severity_t sev_type, const ocsd_err_t code,
          const ocsd_trc_index_t idx);
ocsdError(const ocsd_err_severity_t sev_type, const ocsd_err_t code,
          const ocsd_trc_index_t idx, const uint8_t chan_id);
ocsdError(const ocsd_err_severity_t sev_type, const ocsd_err_t code,
          const std::string &msg);
ocsdError(const ocsd_err_severity_t sev_type, const ocsd_err_t code,
          const ocsd_trc_index_t idx, const std::string &msg);
ocsdError(const ocsd_err_severity_t sev_type, const ocsd_err_t code,
          const ocsd_trc_index_t idx, const uint8_t chan_id, const std::string &msg);
```

**Error Severity Levels:**
| Level | Usage |
|-------|-------|
| `OCSD_ERR_SEV_FATAL` | Decode cannot continue |
| `OCSD_ERR_SEV_ERROR` | Significant issue, try recovery |
| `OCSD_ERR_SEV_WARN` | Recovered from issue, informational |
| `OCSD_ERR_SEV_INFO` | Informational |
| `OCSD_ERR_SEV_DEBUG` | Debugging level |

### 5.2 Error Logger

**Class:** `ocsdDefaultErrorLogger` ([decoder/include/common/ocsd_error_logger.h](decoder/include/common/ocsd_error_logger.h))

Default error logging implementation with these features:

**Key Methods:**
```cpp
bool initErrorLogger(const ocsd_err_severity_t verbosity, 
                     bool bCreateOutputLogger = false);

virtual const ocsd_hndl_err_log_t RegisterErrorSource(
    const std::string &component_name);

virtual void LogError(const ocsd_hndl_err_log_t handle, 
                      const ocsdError *Error);

virtual void LogMessage(const ocsd_hndl_err_log_t handle,
                        const ocsd_err_severity_t filter_level,
                        const std::string &msg);

virtual ocsdError *GetLastError();
virtual ocsdError *GetLastIDError(const uint8_t chan_id);
```

**Features:**
- Per-component error source registration
- Per-CSID error tracking (128 channels max)
- Verbosity filtering
- Optional stderr output logger
- Last error caching

### 5.3 Component Logging Integration

**TraceComponent** provides error logging to all components:

```cpp
void LogError(const ocsdError &Error);
void LogMessage(const ocsd_err_severity_t filter_level, 
                const std::string &msg);
const ocsd_err_severity_t getErrorLogLevel() const;
const bool isLoggingErrorLevel(const ocsd_err_severity_t level) const;
```

**Pattern:**
1. Components get error logger handle via TraceComponent
2. Create ocsdError with context
3. Call LogError() with handle and error
4. Logger automatically routes to registered logger interface

---

## 6. KEY BASE INTERFACES

### 6.1 OcsdCodeFollower

**Class:** `OcsdCodeFollower` ([decoder/include/common/ocsd_code_follower.h](decoder/include/common/ocsd_code_follower.h))

Code executor used for instruction trace decoding:

**Purpose:** Follow code execution to resolve address ranges from atom packets.

**Setup Methods:**
```cpp
void initInterfaces(componentAttachPt<ITargetMemAccess> *pMemAccess,
                    componentAttachPt<IInstrDecode> *pIDecode);
void setArchProfile(const ocsd_arch_profile_t profile);
void setMemSpaceAccess(const ocsd_mem_space_acc_t mem_acc_rule);
void setMemSpaceCSID(const uint8_t csid);
void setISA(const ocsd_isa isa);
void setDSBDMBasWP();
```

**Execution Methods:**
```cpp
ocsd_err_t followSingleAtom(const ocsd_vaddr_t addrStart, 
                            const ocsd_atm_val A);
// Additional methods for multi-instruction following
```

**Results API:**
```cpp
const ocsd_vaddr_t getRangeSt() const;  // inclusive start
const ocsd_vaddr_t getRangeEn() const;  // exclusive end
const bool hasRange() const;
const ocsd_vaddr_t getNextAddr() const;
const ocsd_instr_type getInstrType() const;
const ocsd_instr_subtype getInstrSubType() const;
const bool ISAChanged() const;
```

### 6.2 Memory Access Interface

**Class:** `ITargetMemAccess` (interfaces/trc_tgt_mem_access_i.h)

**Purpose:** Access target memory for instruction fetching and operand reading.

**Key Methods:**
```cpp
virtual ocsd_err_t ReadTargetMemory(const ocsd_vaddr_t address,
                                    const ocsd_mem_space_acc_t mem_space,
                                    uint32_t *num_bytes,
                                    uint8_t *p_buffer) = 0;
virtual ocsd_err_t InvalidateMemAccCache(const ocsd_vaddr_t s_address,
                                         const ocsd_vaddr_t e_address) = 0;
```

### 6.3 Instruction Decode Interface

**Class:** `IInstrDecode` (interfaces/trc_instr_decode_i.h)

**Purpose:** Decode instructions to extract type, operands, targets.

**Key Methods:**
```cpp
virtual ocsd_err_t DecodeInstruction(ocsd_instr_info *instr_info) = 0;
```

### 6.4 Decoder Registration

**Class:** `OcsdLibDcdRegister` ([decoder/include/common/ocsd_lib_dcd_register.h](decoder/include/common/ocsd_lib_dcd_register.h))

Singleton registry for all protocol decoders:

**Key Methods:**
```cpp
static OcsdLibDcdRegister *getDecoderRegister();

const ocsd_err_t registerDecoderTypeByName(
    const std::string &name,
    IDecoderMngr *p_decoder_fact);

const ocsd_err_t getDecoderMngrByName(
    const std::string &name,
    IDecoderMngr **p_decoder_mngr);

const ocsd_err_t getDecoderMngrByType(
    const ocsd_trace_protocol_t decoderType,
    IDecoderMngr **p_decoder_mngr);

const bool isRegisteredDecoder(const std::string &name);
const bool getFirstNamedDecoder(std::string &name);
const bool getNextNamedDecoder(std::string &name);
```

**Built-in Decoders (registered automatically):**
- ETMv3
- ETMv4
- PTM
- STM
- ITM
- ETE

---

## 7. COMPONENT RELATIONSHIPS AND DATA FLOW

### 7.1 Full Decode Pipeline Example (ETMv4)

```
Application
    ↓ (raw trace data)
DecodeTree::TraceDataIn()
    ↓
TraceFormatterFrameDecoder::TraceDataIn()
  (demultiplexes by CSID)
    ↓ (per CSID: bytes)
TrcPktProcEtmV4I::TraceDataIn()
  (parses bytes → ETMv4 packets)
    ↓ (packet by packet)
TrcPktDecodeEtmV4I::PacketDataIn()
  (converts packets → generic elements)
    ↓ (generic elements)
ITrcGenElemIn::TraceElemIn()
  (analysis module consumes elements)
    ↓
Analysis Results
```

### 7.2 Attachment Point Chain

```
Error Logger (attached to all components)
    ↓
TraceComponent
    ├── Frame Deformatter
    │   ├── → ITrcDataIn (input)
    │   ├── → [multiple] ITrcDataIn (output per CSID)
    │   └── → ITraceErrorLog
    │
    ├── Packet Processor (per protocol, per CSID)
    │   ├── → ITrcDataIn (input from deformatter)
    │   ├── → IPktDataIn (output to decoder)
    │   └── → ITraceErrorLog
    │
    └── Packet Decoder (per protocol, per CSID)
        ├── → IPktDataIn (input from processor)
        ├── → ITrcGenElemIn (output to analysis)
        ├── → ITargetMemAccess (optional)
        ├── → IInstrDecode (optional)
        └── → ITraceErrorLog
```

---

## 8. ARCHITECTURAL PATTERNS AND DESIGN PRINCIPLES

### 8.1 Template-Based Type Safety

**Pattern:** Templated base classes ensure compile-time type checking for packets and configurations.

**Example:**
```cpp
template <class P, class Pt, class Pc> 
class TrcPktProcBase : public TrcPktProcI {
    // P: Packet class (EtmV4ITrcPacket)
    // Pt: Packet type enum (ocsd_etmv4_i_pkt_type)
    // Pc: Config class (EtmV4Config)
};
```

**Benefits:**
- No runtime type checking needed
- Compiler catches mismatches
- Same base logic for all protocols
- Reduced enum confusion

### 8.2 Component Attachment Points

**Pattern:** `componentAttachPt<I>` template provides flexible wiring without coupling.

**Features:**
- Supports attach/detach at runtime
- Multiple attachment support (for monitors)
- Enable/disable without detaching
- Used for: error loggers, data inputs, data outputs

**Pattern:**
```cpp
componentAttachPt<ITrcDataIn> m_data_input;
componentAttachPt<ITrcGenElemIn> m_trc_elem_out;
// Usage: getPacketOutAttachPt()->attachComponent(consumer);
```

### 8.3 Configuration Separation

**Pattern:** Configuration objects (`*Config` classes) separate configuration data from processing logic.

**Benefits:**
- Configuration validation in one place
- Easy serialization/deserialization
- Protocol-specific config doesn't leak into decoders
- Factory pattern for config creation

### 8.4 Manager Pattern

**Pattern:** Protocol-specific manager (`IDecoderMngr` implementations) handles:
- Decoder instantiation
- Component attachment
- Configuration creation
- Protocol constants

**Benefits:**
- Encapsulates protocol specifics
- Uniform interface for all protocols
- Easy to add custom decoders
- Factory method pattern

### 8.5 Singleton Registry

**Pattern:** `OcsdLibDcdRegister` uses singleton pattern to maintain global decoder registry.

**Benefits:**
- Single entry point for decoder lookup
- Automatic built-in decoder registration
- Support for custom decoders
- Access by name or protocol type

---

## 9. KEY DESIGN PRINCIPLES

### 9.1 Separation of Concerns

- **Frame deformatter:** Only demultiplexing, not decoding
- **Packet processor:** Only parsing, not interpretation
- **Packet decoder:** Only interpretation, not output formatting
- **Analysis module:** Only consumption of generic elements

### 9.2 Interface-Based Composition

- All major components use interfaces (`ITrc*`)
- Enables mocking, testing, and extension
- No hard-coded dependencies
- Attachment points for flexible wiring

### 9.3 Flow Control

- Datapath response codes enable backpressure
- Components can signal "WAIT" upstream
- No data loss on backpressure
- Supports streaming and batch processing

### 9.4 Error Context

- Errors carry trace index and channel ID
- Enables error source identification
- Full context for error reporting
- Per-component error tracking

### 9.5 Protocol Consistency

- All protocols follow same structural pattern
- Same base classes/interfaces across protocols
- Consistent naming conventions
- Templates reduce duplicated logic

---

## 10. CONFIGURATION AND INITIALIZATION

### 10.1 Protocol Configuration Classes

Each protocol has a configuration class (e.g., `EtmV4Config`) that:
- Stores protocol register values
- Validates configuration parameters
- Provides access to configuration data
- Derived from base `CSConfig` class

### 10.2 Decoder Creation Flow

```
1. Application gets decoder manager for protocol
   → OcsdLibDcdRegister::getDecoderMngrByType()

2. Manager creates protocol config object
   → IDecoderMngr::createConfigFromDataStruct()

3. Manager creates decoder instance with config
   → IDecoderMngr::createDecoder()

4. Application attaches optional components
   → attachMemAccessor(), attachInstrDecoder(), etc.

5. Application attaches output sink
   → attachOutputSink()

6. Application attaches error logger
   → attachErrorLogger()

7. Decoder ready for trace data
   → TraceDataIn() calls begin
```

---

## 11. SUMMARY TABLE: PROTOCOL FEATURES

| Feature | ETMv4 | ETMv3 | PTM | STM | ITM | ETE |
|---------|-------|-------|-----|-----|-----|-----|
| **Type** | Instruction | Instruction | Instruction | Software | Software | Instruction |
| **Speculation** | Yes | No | No | N/A | N/A | Yes |
| **Atoms** | Single/Multi | Single | Single | N/A | N/A | Single/Multi |
| **Timestamps** | Yes | Yes | Yes | Yes | Yes | Yes |
| **Cycle Count** | Yes | Yes | Yes | No | No | Yes |
| **Exceptions** | Yes | Yes | Yes | No | No | Yes |
| **Address Sync** | Yes | Yes | Yes | No | No | Yes |
| **Conditional** | Yes | Yes | No | No | No | Yes |
| **Memory Access** | Optional | Optional | Optional | No | No | Optional |
| **Instruction Decode** | Required | Required | Required | No | No | Required |

---

## CONCLUSION

The OpenCSD C++ decoder architecture is a sophisticated, well-designed system that demonstrates:

1. **Layered Design:** Clear separation across frame deformatting, packet processing, and decoding
2. **Template Metaprogramming:** Type-safe packet and decoder abstractions
3. **Interface-Based Extensibility:** Plugin architecture for custom decoders and modules
4. **Comprehensive Error Handling:** Context-aware error reporting throughout
5. **Consistent Patterns:** All protocols follow same structural organization
6. **Flow Control:** Backpressure-aware data streaming with operation semantics
7. **Component Composition:** Flexible attachment of optional modules (memory access, instruction decode)

The architecture supports ARM's evolving trace protocol landscape while maintaining clean abstractions and consistent patterns across diverse implementations.
