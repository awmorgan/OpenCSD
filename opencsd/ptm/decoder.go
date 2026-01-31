package ptm

import (
	"encoding/binary"
	"fmt"

	"opencsd/common"
)

// Decoder handles PTM trace decoding and maintains decoder state
type Decoder struct {
	// Configuration
	TraceID        uint8                 // Trace source ID
	Log            common.Logger         // Logger for errors and debug info
	MemAcc         common.MemoryAccessor // Memory accessor for reading instruction opcodes
	CycleAccEnable bool                  // Cycle accurate tracing enabled

	// Current element being built
	CurrentElement *common.GenericTraceElement

	// Synchronization state
	syncFound     bool // true once we've seen ASYNC + ISYNC
	waitingISync  bool // true after ASYNC, waiting for ISYNC
	noSyncEmitted bool // true once NO_SYNC has been emitted for this decode run

	// Current processor context - valid indicates we have a good address from ISYNC/BranchAddr
	currentAddr    uint64                // Current program counter
	addrValid      bool                  // True if currentAddr is valid (set by ISYNC/BranchAddr)
	lastPacketAddr uint64                // Last packet-reported address (for address reconstruction)
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

	// Return stack for indirect returns - stores (address, ISA) pairs
	retStack    []uint64     // Return addresses
	retStackISA []common.ISA // ISA at each return address

	// Current packet cycle count (to be attached to output elements)
	currPktCycleCount uint32 // Cycle count from current packet
	currPktHasCC      bool   // True if current packet has cycle count

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
	d.noSyncEmitted = false
	d.currentAddr = 0
	d.addrValid = false
	d.lastPacketAddr = 0
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
	d.retStack = nil
	d.retStackISA = nil
	d.currPktCycleCount = 0
	d.currPktHasCC = false
}

// ProcessPacket processes a single packet and updates decoder state
// Returns any generated trace elements
func (d *Decoder) ProcessPacket(pkt Packet) ([]common.GenericTraceElement, error) {
	d.elements = nil // Clear previous elements

	// Track current packet's cycle count
	d.currPktCycleCount = pkt.CycleCount
	d.currPktHasCC = pkt.CCValid

	switch pkt.Type {
	case PacketTypeASYNC:
		return d.processASYNC(pkt)

	case PacketTypeISYNC:
		return d.processISync(pkt)

	case PacketTypeBranchAddr:
		return d.processBranchAddress(pkt)

	case PacketTypeATOM:
		return d.processAtomPacket(pkt)

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
		if !d.noSyncEmitted {
			elem := common.GenericTraceElement{
				Type: common.ElemTypeNoSync,
			}
			d.elements = append(d.elements, elem)
			d.noSyncEmitted = true
		}
	}
	return d.elements, nil
}

// processISync handles ISYNC packets - establishes synchronization
func (d *Decoder) processISync(pkt Packet) ([]common.GenericTraceElement, error) {
	wasSynced := d.syncFound
	if !d.syncFound {
		// First sync
		d.syncFound = true
		d.waitingISync = false
		d.Log.Logf(common.SeverityInfo, "Synchronization established at address 0x%x", pkt.Address)

		// Generate NO_SYNC element first (if we weren't synced before)
		if !d.noSyncEmitted {
			elem := common.GenericTraceElement{
				Type: common.ElemTypeNoSync,
			}
			d.elements = append(d.elements, elem)
			d.noSyncEmitted = true
		}
	}

	prevISA := d.currentISA
	prevCtx := d.contextID
	prevVMID := d.vmid
	prevSec := d.secureState

	// Update context from ISYNC
	d.currentAddr = pkt.Address
	d.addrValid = true // ISYNC provides a valid address
	d.lastPacketAddr = pkt.Address
	d.currentISA = pkt.ISA
	if pkt.SecureValid {
		d.secureState = pkt.SecureState
	}
	d.contextID = pkt.ContextID
	if pkt.VMID != 0 {
		d.vmid = pkt.VMID
	}

	// Generate TRACE_ON element if required
	if !wasSynced || pkt.ISyncReason != ISyncPeriodic {
		reason := "trace enable"
		if pkt.ISyncReason == ISyncDebugExit {
			reason = "debug restart"
		}

		traceOnElem := common.GenericTraceElement{
			Type:          common.ElemTypeTraceOn,
			TraceOnReason: reason,
		}
		if pkt.CCValid {
			traceOnElem.CycleCount = pkt.CycleCount
			traceOnElem.HasCycleCount = true
		}
		d.elements = append(d.elements, traceOnElem)
	}

	// Generate PE_CONTEXT only if context changed or first sync
	contextChanged := !wasSynced || (pkt.ISAValid && pkt.ISA != prevISA) || (pkt.SecureValid && pkt.SecureState != prevSec) || (d.contextID != prevCtx) || (d.vmid != prevVMID)
	if contextChanged {
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
	}

	d.Log.Logf(common.SeverityDebug, "ISYNC: addr=0x%x ISA=%s", d.currentAddr, d.currentISA)

	return d.elements, nil
}

// processBranchAddress handles branch address packets - updates PC
func (d *Decoder) processBranchAddress(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		// Not synchronized yet, ignore
		return nil, nil
	}

	prevAddr := d.currentAddr
	addr := pkt.Address
	if pkt.AddrBits > 0 {
		mask := (uint64(1) << pkt.AddrBits) - 1
		addr = (d.lastPacketAddr & ^mask) | (addr & mask)
	}

	if pkt.ISAValid {
		d.currentISA = pkt.ISA
	}
	if pkt.SecureValid {
		d.secureState = pkt.SecureState
	}

	// Check if this is an exception
	if pkt.ExceptionNum != 0 {
		// Generate exception element
		elem := common.GenericTraceElement{
			Type: common.ElemTypeException,
			Exception: common.ExceptionInfo{
				Number:      pkt.ExceptionNum,
				Type:        d.getExceptionType(pkt.ExceptionNum),
				PrefRetAddr: prevAddr, // Previous address
			},
		}
		if d.currPktHasCC {
			elem.CycleCount = d.currPktCycleCount
			elem.HasCycleCount = true
		}
		d.elements = append(d.elements, elem)
		d.Log.Logf(common.SeverityDebug, "Exception: num=0x%x at addr=0x%x", pkt.ExceptionNum, prevAddr)
	} else if d.MemAcc != nil && d.addrValid {
		// Branch address only (no exception) implies an E atom
		// Need to trace from current address to the branch waypoint
		_, err := d.traceToWaypoint(common.AtomExecuted)
		if err != nil {
			d.Log.Logf(common.SeverityWarning, "Failed to trace to waypoint: %v", err)
			return d.elements, err
		}
	}

	// Update current address to the branch target from packet
	d.currentAddr = addr
	d.addrValid = true // Branch address provides a valid address
	d.lastPacketAddr = addr
	d.Log.Logf(common.SeverityDebug, "Branch to address: 0x%x", d.currentAddr)

	return d.elements, nil
}

// traceToWaypoint traces instructions from currentAddr until a branch is found.
// This emits an INSTR_RANGE element and updates currentAddr.
// The atom parameter indicates if the branch was executed (E) or not (N).
// Returns true if successful, false if a memory access error occurred (ADDR_NACC emitted).
func (d *Decoder) traceToWaypoint(atom common.Atom) (bool, error) {
	if d.MemAcc == nil {
		return false, fmt.Errorf("memory accessor not set")
	}

	if !d.addrValid {
		// No valid address to trace from, skip this atom
		return false, nil
	}

	rangeStart := d.currentAddr
	instrCount := uint32(0)
	var lastInstrInfo *common.InstrInfo
	lastExec := atom == common.AtomExecuted

	// Walk instructions until we hit a branch
	for step := 0; step < 4096; step++ {
		prevAddr := d.currentAddr
		instrInfo, err := d.decodeInstruction(prevAddr)
		if err != nil {
			// Memory access error - emit ADDR_NACC and invalidate address
			d.Log.Logf(common.SeverityWarning, "Memory access error at 0x%X: %v", prevAddr, err)
			elem := common.GenericTraceElement{
				Type:         common.ElemTypeAddrNacc,
				NaccAddr:     prevAddr,
				NaccMemSpace: d.getSecurityState(),
			}
			d.elements = append(d.elements, elem)
			d.addrValid = false // Need ISYNC or BranchAddr to resync
			return false, nil   // Not a fatal error, just need to wait for resync
		}
		lastInstrInfo = instrInfo
		instrCount++
		nextAddr := prevAddr + uint64(instrInfo.Size)

		if instrInfo.IsBranch {
			executed := atom == common.AtomExecuted
			if !instrInfo.IsConditional {
				executed = true
			}
			lastExec = executed

			if executed && instrInfo.IsLink {
				// Push return address with current ISA for return stack
				d.retStack = append(d.retStack, nextAddr)
				d.retStackISA = append(d.retStackISA, d.currentISA)
			}

			if executed {
				if instrInfo.HasBranchTarget {
					d.currentAddr = instrInfo.BranchTarget
				} else if instrInfo.Type == common.InstrTypeBranchIndirect && instrInfo.IsReturn && len(d.retStack) > 0 {
					target := d.retStack[len(d.retStack)-1]
					targetISA := d.retStackISA[len(d.retStackISA)-1]
					d.retStack = d.retStack[:len(d.retStack)-1]
					d.retStackISA = d.retStackISA[:len(d.retStackISA)-1]
					d.currentAddr = target
					d.currentISA = targetISA
				} else {
					d.currentAddr = nextAddr
				}
			} else {
				d.currentAddr = nextAddr
			}

			// Emit range on branch
			elem := common.GenericTraceElement{
				Type: common.ElemTypeAddrRange,
				AddrRange: common.AddrRange{
					StartAddr:       rangeStart,
					EndAddr:         nextAddr,
					ISA:             d.currentISA,
					NumInstr:        instrCount,
					LastInstrSz:     uint8(instrInfo.Size),
					LastInstrExec:   lastExec,
					LastInstrType:   instrInfo.Type,
					LastInstrCond:   instrInfo.IsConditional,
					LastInstrLink:   instrInfo.IsLink,
					LastInstrReturn: instrInfo.IsReturn,
				},
			}
			if d.currPktHasCC {
				elem.CycleCount = d.currPktCycleCount
				elem.HasCycleCount = true
			}
			d.elements = append(d.elements, elem)
			d.Log.Logf(common.SeverityDebug, "  -> ADDR_RANGE: 0x%X-0x%X (%d instrs)", rangeStart, nextAddr, instrCount)

			// Update ISA for next instruction if branch was taken
			if executed && instrInfo.NextISAValid {
				d.currentISA = instrInfo.NextISA
			}

			return true, nil
		}

		// Non-branch: advance and continue
		d.currentAddr = nextAddr
	}

	if lastInstrInfo == nil {
		return false, fmt.Errorf("no instruction decoded starting at 0x%X", rangeStart)
	}

	return false, fmt.Errorf("no branch found within 4096 instructions starting at 0x%X", rangeStart)
}

// processAtomPacket handles atom packets - tracks executed instructions
func (d *Decoder) processAtomPacket(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	// Check if we have memory access
	if d.MemAcc == nil {
		d.Log.Warning("Cannot process atoms without memory accessor")
		return nil, nil
	}

	// Set cycle count from packet
	if pkt.CCValid {
		d.currPktCycleCount = pkt.CycleCount
		d.currPktHasCC = true
	} else {
		d.currPktHasCC = false
	}

	d.Log.Logf(common.SeverityDebug, "Atom: %d atoms, pattern=0x%x", pkt.AtomCount, pkt.AtomBits)

	for i := uint8(0); i < pkt.AtomCount; i++ {
		// If address is not valid (after ADDR_NACC), skip remaining atoms
		if !d.addrValid {
			break
		}

		// Get the atom bit (E = 1 = executed, N = 0 = not executed)
		atomBit := (pkt.AtomBits >> i) & 1
		atom := common.AtomNotExecuted
		if atomBit == 1 {
			atom = common.AtomExecuted
		}

		_, err := d.traceToWaypoint(atom)
		if err != nil {
			d.Log.Logf(common.SeverityWarning, "Failed to trace to waypoint for atom %d: %v", i, err)
			return d.elements, err
		}
	}

	return d.elements, nil
}

// processAtom advances currentAddr based on a single atom bit.
func (d *Decoder) processAtom(atomBit common.Atom) (*common.InstrInfo, bool, error) {
	if d.MemAcc == nil {
		return nil, false, fmt.Errorf("memory accessor not set")
	}

	buf := make([]byte, 4)
	n, err := d.MemAcc.ReadTargetMemory(d.currentAddr, buf)
	if err != nil {
		return nil, false, err
	}
	if n < 4 {
		return nil, false, fmt.Errorf("incomplete instruction read at 0x%X: got %d bytes", d.currentAddr, n)
	}

	opcode := binary.LittleEndian.Uint32(buf)
	decoder := NewInstrDecoder(d.currentISA)

	var instrInfo *common.InstrInfo
	if d.currentISA == common.ISAARM {
		instrInfo, err = decoder.DecodeARMOpcode(d.currentAddr, opcode)
	} else {
		instrInfo, err = decoder.DecodeInstruction(d.currentAddr, d.MemAcc)
	}
	if err != nil {
		return nil, false, err
	}

	nextAddr := d.currentAddr + uint64(instrInfo.Size)
	branchTaken := false
	if atomBit == common.AtomExecuted && instrInfo.IsLink {
		d.retStack = append(d.retStack, nextAddr)
		d.retStackISA = append(d.retStackISA, d.currentISA)
	}

	if atomBit == common.AtomExecuted {
		if instrInfo.IsBranch && instrInfo.HasBranchTarget {
			d.currentAddr = instrInfo.BranchTarget
			branchTaken = true
		} else if instrInfo.Type == common.InstrTypeBranchIndirect && instrInfo.IsReturn && len(d.retStack) > 0 {
			// Use return stack for indirect returns
			target := d.retStack[len(d.retStack)-1]
			targetISA := d.retStackISA[len(d.retStackISA)-1]
			d.retStack = d.retStack[:len(d.retStack)-1]
			d.retStackISA = d.retStackISA[:len(d.retStackISA)-1]
			d.currentAddr = target
			d.currentISA = targetISA
			branchTaken = true
		} else {
			d.currentAddr = nextAddr
			if instrInfo.IsBranch {
				branchTaken = true
			}
		}
	} else {
		// Not executed/not taken - fall through
		d.currentAddr = nextAddr
		if instrInfo.IsBranch {
			branchTaken = true
		}
	}

	return instrInfo, branchTaken, nil
}

func (d *Decoder) decodeInstruction(addr uint64) (*common.InstrInfo, error) {
	if d.MemAcc == nil {
		return nil, fmt.Errorf("memory accessor not set")
	}

	buf := make([]byte, 4)
	n, err := d.MemAcc.ReadTargetMemory(addr, buf)
	if err != nil {
		return nil, err
	}
	if n < 4 {
		return nil, fmt.Errorf("incomplete instruction read at 0x%X: got %d bytes", addr, n)
	}

	decoder := NewInstrDecoder(d.currentISA)
	if d.currentISA == common.ISAARM {
		opcode := binary.LittleEndian.Uint32(buf)
		return decoder.DecodeARMOpcode(addr, opcode)
	}

	return decoder.DecodeInstruction(addr, d.MemAcc)
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
	if d.currPktHasCC {
		elem.CycleCount = d.currPktCycleCount
		elem.HasCycleCount = true
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
