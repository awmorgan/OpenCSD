package ptm

import (
	"fmt"

	"opencsd/common"
)

// Decoder handles PTM trace decoding and maintains decoder state
type Decoder struct {
	// Configuration
	TraceID uint8                   // Trace source ID
	Log     common.Logger           // Logger for errors and debug info
	MemAcc  common.MemoryAccessor   // Memory accessor for reading instruction opcodes

	// Current element being built
	CurrentElement *common.GenericTraceElement

	// Synchronization state
	syncFound    bool // true once we've seen ASYNC + ISYNC
	waitingISync bool // true after ASYNC, waiting for ISYNC

	// Current processor context
	currentAddr    uint64                // Current program counter
	currentISA     common.ISA            // Current instruction set
	secureState    bool                  // Current security state (S/N)
	contextID      uint32                // Current context ID
	vmid           uint8                 // Current VMID
	exceptionLevel common.ExceptionLevel // Current exception level

	// Atom tracking (for instruction execution)
	atomPending bool  // Have atoms waiting to be processed
	atomBits    uint8 // E/N pattern
	atomCount   uint8 // Number of atoms
	atomIndex   uint8 // Current atom being processed

	// Output elements
	elements []common.GenericTraceElement // Decoded trace elements
}

// NewDecoder creates a new PTM decoder for the given trace ID
func NewDecoder(traceID uint8) *Decoder {
	return &Decoder{
		TraceID: traceID,
		Log:     common.NewNoOpLogger(), // Default to no-op logger
	}
}

// NewDecoderWithLogger creates a new PTM decoder with a custom logger
func NewDecoderWithLogger(traceID uint8, logger common.Logger) *Decoder {
	return &Decoder{
		TraceID: traceID,
		Log:     logger,
	}
}

// SetMemoryAccessor sets the memory accessor for reading instruction opcodes.
// This is required for decoding Atom packets, which need to read opcodes
// to determine branch targets.
func (d *Decoder) SetMemoryAccessor(memAcc common.MemoryAccessor) {
	d.MemAcc = memAcc
}

// Reset resets the decoder state
func (d *Decoder) Reset() {
	d.syncFound = false
	d.waitingISync = false
	d.currentAddr = 0
	d.currentISA = common.ISAARM
	d.secureState = false
	d.contextID = 0
	d.vmid = 0
	d.exceptionLevel = common.EL0
	d.atomPending = false
	d.atomBits = 0
	d.atomCount = 0
	d.atomIndex = 0
	d.elements = nil
	d.CurrentElement = nil
}

// ProcessPacket processes a single packet and updates decoder state
// Returns any generated trace elements
func (d *Decoder) ProcessPacket(pkt Packet) ([]common.GenericTraceElement, error) {
	d.elements = nil // Clear previous elements

	switch pkt.Type {
	case PacketTypeASYNC:
		return d.processASYNC(pkt)

	case PacketTypeISYNC:
		return d.processISync(pkt)

	case PacketTypeBranchAddr:
		return d.processBranchAddress(pkt)

	case PacketTypeATOM:
		return d.processAtom(pkt)

	case PacketTypeTimestamp:
		return d.processTimestamp(pkt)

	case PacketTypeContextID:
		return d.processContextID(pkt)

	case PacketTypeVMID:
		return d.processVMID(pkt)

	case PacketTypeExceptionReturn:
		return d.processExceptionReturn(pkt)

	case PacketTypeUnknown:
		// Ignore unknown packets
		d.Log.Logf(common.SeverityDebug, "Ignoring unknown packet at offset %d", pkt.Offset)
		return nil, nil

	default:
		return nil, fmt.Errorf("unhandled packet type: %s", pkt.Type)
	}
}

// processASYNC handles ASYNC packets - signals start of sync sequence
func (d *Decoder) processASYNC(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		d.Log.Debug("ASYNC packet received, waiting for ISYNC")
		d.waitingISync = true
	}
	return nil, nil
}

// processISync handles ISYNC packets - establishes synchronization
func (d *Decoder) processISync(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		// First sync
		d.syncFound = true
		d.waitingISync = false
		d.Log.Logf(common.SeverityInfo, "Synchronization established at address 0x%x", pkt.Address)

		// Generate NO_SYNC element first (if we weren't synced before)
		elem := common.GenericTraceElement{
			Type: common.ElemTypeNoSync,
		}
		d.elements = append(d.elements, elem)
	}

	// Update context from ISYNC
	d.currentAddr = pkt.Address
	d.currentISA = pkt.ISA
	d.secureState = pkt.SecureState
	d.contextID = pkt.ContextID

	// Generate TRACE_ON element
	reason := "trace enable"
	if pkt.ISyncReason == ISyncDebugExit {
		reason = "debug restart"
	}

	traceOnElem := common.GenericTraceElement{
		Type:          common.ElemTypeTraceOn,
		TraceOnReason: reason,
	}
	d.elements = append(d.elements, traceOnElem)

	// Generate PE_CONTEXT element
	ctxElem := common.GenericTraceElement{
		Type: common.ElemTypePeContext,
		Context: common.PEContext{
			ContextID:      d.contextID,
			VMID:           uint32(d.vmid),
			ISA:            d.currentISA,
			SecurityState:  d.getSecurityState(),
			ExceptionLevel: d.exceptionLevel,
		},
	}
	d.elements = append(d.elements, ctxElem)

	d.Log.Logf(common.SeverityDebug, "ISYNC: addr=0x%x ISA=%s", d.currentAddr, d.currentISA)

	return d.elements, nil
}

// processBranchAddress handles branch address packets - updates PC
func (d *Decoder) processBranchAddress(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		// Not synchronized yet, ignore
		return nil, nil
	}

	// Extract address from packet
	// For now, we do a simple extraction - this needs proper implementation
	// based on the PTM specification for address compression
	addr := d.extractBranchAddress(pkt)

	// Check if this is an exception
	if pkt.ExceptionNum != 0 {
		// Generate exception element
		elem := common.GenericTraceElement{
			Type: common.ElemTypeException,
			Exception: common.ExceptionInfo{
				Number:      pkt.ExceptionNum,
				Type:        d.getExceptionType(pkt.ExceptionNum),
				PrefRetAddr: d.currentAddr, // Previous address
			},
		}
		d.elements = append(d.elements, elem)
		d.Log.Logf(common.SeverityDebug, "Exception: num=0x%x at addr=0x%x", pkt.ExceptionNum, d.currentAddr)
	}

	// Update current address
	d.currentAddr = addr
	d.Log.Logf(common.SeverityDebug, "Branch to address: 0x%x", d.currentAddr)

	return d.elements, nil
}

// processAtom handles atom packets - tracks executed instructions
func (d *Decoder) processAtom(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	// Store atom pattern for later processing
	d.atomPending = true
	d.atomBits = pkt.AtomBits
	d.atomCount = pkt.AtomCount
	d.atomIndex = 0

	d.Log.Logf(common.SeverityDebug, "Atom: %d atoms, pattern=0x%x", d.atomCount, d.atomBits)

	// TODO: To fully decode atoms, we need to:
	// 1. Read instruction opcodes from memory using d.MemAcc.ReadMemory(d.currentAddr, buf)
	// 2. Disassemble each instruction to determine if it's a branch
	// 3. For each atom bit:
	//    - E (executed): instruction executed, advance PC
	//    - N (not executed): branch not taken, skip instruction
	// 4. Calculate address ranges and generate ADDR_RANGE elements
	//
	// This is the "Hard Wall" - atoms require memory access and instruction disassembly.

	return nil, nil
}

// processTimestamp handles timestamp packets
func (d *Decoder) processTimestamp(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	elem := common.GenericTraceElement{
		Type:      common.ElemTypeTimestamp,
		Timestamp: pkt.Timestamp,
	}
	d.elements = append(d.elements, elem)

	d.Log.Logf(common.SeverityDebug, "Timestamp: 0x%x", pkt.Timestamp)

	return d.elements, nil
}

// processContextID handles context ID packets
func (d *Decoder) processContextID(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	d.contextID = pkt.ContextID
	d.Log.Logf(common.SeverityDebug, "Context ID updated: 0x%x", d.contextID)

	// Generate PE_CONTEXT element with updated context
	elem := common.GenericTraceElement{
		Type: common.ElemTypePeContext,
		Context: common.PEContext{
			ContextID:      d.contextID,
			VMID:           uint32(d.vmid),
			ISA:            d.currentISA,
			SecurityState:  d.getSecurityState(),
			ExceptionLevel: d.exceptionLevel,
		},
	}
	d.elements = append(d.elements, elem)

	return d.elements, nil
}

// processVMID handles VMID packets
func (d *Decoder) processVMID(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	d.vmid = pkt.VMID
	d.Log.Logf(common.SeverityDebug, "VMID updated: 0x%x", d.vmid)

	return nil, nil
}

// processExceptionReturn handles exception return packets
func (d *Decoder) processExceptionReturn(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	elem := common.GenericTraceElement{
		Type: common.ElemTypeExceptionReturn,
	}
	d.elements = append(d.elements, elem)

	d.Log.Logf(common.SeverityDebug, "Exception return")

	return d.elements, nil
}

// Helper functions

func (d *Decoder) getSecurityState() common.SecurityState {
	if d.secureState {
		return common.SecurityStateSecure
	}
	return common.SecurityStateNonSecure
}

func (d *Decoder) extractBranchAddress(pkt Packet) uint64 {
	// Simplified address extraction
	// In a full implementation, this would handle address compression
	// For now, just extract what we can from the packet data
	if len(pkt.Data) < 2 {
		return 0
	}

	// Basic extraction - needs proper implementation
	addr := uint64(0)
	for i := 1; i < len(pkt.Data) && i < 6; i++ {
		b := pkt.Data[i]
		// Remove continuation bit
		addr |= uint64(b&0x7F) << ((i - 1) * 7)
	}

	return addr
}

func (d *Decoder) getExceptionType(num uint16) string {
	switch num {
	case 0x00:
		return "No Exception"
	case 0x01:
		return "Debug Halt"
	case 0x02:
		return "SMC"
	case 0x03:
		return "Hyp"
	case 0x04:
		return "Async Data Abort"
	case 0x05:
		return "Jazelle"
	case 0x08:
		return "PE Reset"
	case 0x0A:
		return "IRQ"
	case 0x0B:
		return "FIQ"
	default:
		return fmt.Sprintf("Exception %d", num)
	}
}

// IsSynchronized returns true if the decoder has synchronized with the trace stream
func (d *Decoder) IsSynchronized() bool {
	return d.syncFound
}

// GetCurrentAddress returns the current program counter
func (d *Decoder) GetCurrentAddress() uint64 {
	return d.currentAddr
}

// GetCurrentISA returns the current instruction set
func (d *Decoder) GetCurrentISA() common.ISA {
	return d.currentISA
}
