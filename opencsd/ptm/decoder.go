package ptm

import (
	"encoding/binary"
	"fmt"

	"opencsd/common"
)

// DecoderState represents the state machine states for PTM packet processing
type DecoderState int

const (
	StateNoSync DecoderState = iota
	StateWaitSync
	StateWaitISYNC
	StateDecodePkts
	StateContISYNC
	StateContAtom
	StateContWaypoint
	StateContBranch
)

func (s DecoderState) String() string {
	switch s {
	case StateNoSync:
		return "NO_SYNC"
	case StateWaitSync:
		return "WAIT_SYNC"
	case StateWaitISYNC:
		return "WAIT_ISYNC"
	case StateDecodePkts:
		return "DECODE_PKTS"
	case StateContISYNC:
		return "CONT_ISYNC"
	case StateContAtom:
		return "CONT_ATOM"
	case StateContWaypoint:
		return "CONT_WAYPOINT"
	case StateContBranch:
		return "CONT_BRANCH"
	default:
		return "UNKNOWN"
	}
}

// Decoder handles PTM trace decoding and maintains decoder state
type Decoder struct {
	// Configuration
	TraceID             uint8                 // Trace source ID
	Log                 common.Logger         // Logger for errors and debug info
	MemAcc              common.MemoryAccessor // Memory accessor for reading instruction opcodes
	CycleAccEnable      bool                  // Cycle accurate tracing enabled
	RetStackEnable      bool                  // Return stack enabled (from ETMCR bit 29)
	VMIDEnable          bool                  // VMID tracing enabled
	TimestampEnable     bool                  // Timestamp tracing enabled
	Timestamp64Bit      bool                  // Timestamp is 64-bit
	TimestampBinary     bool                  // Timestamp encoding is natural binary
	DsbDmbWaypoint      bool                  // DSB/DMB treated as waypoints
	ContextIDBytes      int                   // Context ID packet size in bytes
	ContextIDConfigured bool                  // Context ID size configured from device

	// Current element being built
	CurrentElement *common.GenericTraceElement

	// Synchronization state
	state         DecoderState // Current decode state machine state
	needISYNC     bool         // Need ISYNC to establish synchronization
	syncFound     bool         // true once we've seen ASYNC + ISYNC
	noSyncEmitted bool         // true once NO_SYNC has been emitted for this decode run

	// Current processor context - valid indicates we have a good address from ISYNC/BranchAddr
	currentAddr    uint64                // Current program counter
	addrValid      bool                  // True if currentAddr is valid (set by ISYNC/BranchAddr)
	lastPacketAddr uint64                // Last packet-reported address (for address reconstruction)
	currentISA     common.ISA            // Current instruction set
	secureState    bool                  // Current security state (S/N)
	contextID      uint32                // Current context ID
	vmid           uint8                 // Current VMID
	exceptionLevel common.ExceptionLevel // Current exception level

	// Parsing state - tracks ISA during packet parsing (before ProcessPacket)
	parseISA common.ISA // ISA state during parsing (updated by ISYNC, used by branch addr)

	// Timestamp state - accumulated timestamp value
	currentTimestamp uint64 // Accumulated timestamp (updated by timestamp packets)

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
		TraceID:        traceID,
		Log:            common.NewNoOpLogger(), // Default to no-op logger
		RetStackEnable: true,                   // Enable return stack by default
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
	d.state = StateNoSync
	d.needISYNC = true
	d.syncFound = false
	d.noSyncEmitted = false
	d.currentAddr = 0
	d.addrValid = false
	d.lastPacketAddr = 0
	d.currentISA = common.ISAARM
	d.parseISA = common.ISAARM
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
	d.currentTimestamp = 0 // Reset accumulated timestamp
}

// ProcessPacket processes a single packet using the decode FSM
// Returns any generated trace elements
func (d *Decoder) ProcessPacket(pkt Packet) ([]common.GenericTraceElement, error) {
	d.elements = nil // Clear previous elements

	// Track current packet's cycle count
	d.currPktCycleCount = pkt.CycleCount
	d.currPktHasCC = pkt.CCValid

	// FSM loop - may process multiple transitions per packet for multi-output sequences
	for {
		switch d.state {
		case StateNoSync:
			// No sync found yet - emit NO_SYNC element and transition
			// Matches C++ behavior: output NO_SYNC on first packet, then transition state
			if !d.noSyncEmitted {
				elem := common.GenericTraceElement{
					Type: common.ElemTypeNoSync,
				}
				d.elements = append(d.elements, elem)
				d.noSyncEmitted = true
				// After emitting NO_SYNC, transition based on packet type and continue
				if pkt.Type == PacketTypeASYNC {
					d.state = StateWaitISYNC
				} else if pkt.Type == PacketTypeISYNC {
					// Allow ISYNC to act as initial sync packet (without ASYNC)
					d.state = StateWaitISYNC
				} else {
					d.state = StateWaitSync
				}
				// Continue processing in the new state
				continue
			} else {
				// NO_SYNC already emitted, shouldn't reach here
				d.state = StateWaitSync
				return d.elements, nil
			}

		case StateWaitSync:
			// Waiting for ASYNC packet - ignore all others
			if pkt.Type == PacketTypeASYNC {
				d.state = StateWaitISYNC
			}
			return d.elements, nil

		case StateWaitISYNC:
			// Waiting for ISYNC packet - ignore others (except ASYNC)
			if pkt.Type == PacketTypeISYNC {
				// Process ISYNC and transition to decode
				// processISync appends to d.elements directly, so no need to append the return value
				_, err := d.processISync(pkt)
				if err != nil {
					return nil, err
				}
				d.syncFound = true
				d.needISYNC = false
				d.state = StateDecodePkts
				return d.elements, nil
			} else if pkt.Type == PacketTypeASYNC {
				// Stay in WAIT_ISYNC
			}
			return d.elements, nil

		case StateDecodePkts:
			// Normal packet processing
			return d.decodePacket(pkt)

		case StateContISYNC:
			// Continuation of ISYNC processing (for multi-element ISYNC sequences)
			return d.decodePacket(pkt)

		case StateContAtom:
			// Continuation of ATOM processing
			return d.decodePacket(pkt)

		case StateContWaypoint:
			// Continuation of waypoint processing
			return d.decodePacket(pkt)

		case StateContBranch:
			// Continuation of branch processing
			return d.decodePacket(pkt)

		default:
			return nil, fmt.Errorf("invalid state: %v", d.state)
		}
	}
}

// decodePacket processes a packet in DECODE_PKTS or continuation states
func (d *Decoder) decodePacket(pkt Packet) ([]common.GenericTraceElement, error) {
	switch pkt.Type {
	case PacketTypeASYNC:
		// ASYNC in decode state - just ignore (resync already happened)
		return d.elements, nil

	case PacketTypeISYNC:
		// ISYNC in decode - establish new context
		return d.processISync(pkt)

	case PacketTypeBranchAddr:
		// Branch address packet
		return d.processBranchAddress(pkt)

	case PacketTypeATOM:
		// Atom packet (execute instructions)
		if d.addrValid {
			return d.processAtomPacket(pkt)
		}
		return d.elements, nil

	case PacketTypeTimestamp:
		// Timestamp packet
		return d.processTimestamp(pkt)

	case PacketTypeContextID:
		// Context ID change
		return d.processContextID(pkt)

	case PacketTypeVMID:
		// VMID change
		return d.processVMID(pkt)

	case PacketTypeExceptionReturn:
		// Exception return
		return d.processExceptionReturn(pkt)

	case PacketTypeTrigger:
		// Trigger packets are logged
		d.Log.Logf(common.SeverityDebug, "Trigger packet at offset %d", pkt.Offset)
		return d.elements, nil

	case PacketTypeWaypoint:
		// Waypoint update packets - trace from current address to waypoint address
		return d.processWaypointUpdate(pkt)

	case PacketTypeIgnore:
		// Ignore packets
		return d.elements, nil

	case PacketTypeBadSequence, PacketTypeReserved:
		// Bad sequence or reserved - need to resync
		d.state = StateWaitSync
		d.needISYNC = true
		elem := common.GenericTraceElement{
			Type: common.ElemTypeNoSync,
		}
		d.elements = append(d.elements, elem)
		return d.elements, nil

	case PacketTypeNoSync, PacketTypeIncompleteEOT:
		// Marker packets - just log
		d.Log.Logf(common.SeverityDebug, "Marker packet %s at offset %d", pkt.Type, pkt.Offset)
		return d.elements, nil

	case PacketTypeUnknown:
		// Ignore unknown packets
		d.Log.Logf(common.SeverityDebug, "Ignoring unknown packet at offset %d", pkt.Offset)
		return d.elements, nil

	default:
		return nil, fmt.Errorf("unhandled packet type: %s", pkt.Type)
	}
}

// processISync handles ISYNC packets - establishes synchronization
func (d *Decoder) processISync(pkt Packet) ([]common.GenericTraceElement, error) {
	wasSynced := d.syncFound
	if !d.syncFound {
		// First sync
		d.syncFound = true
		d.needISYNC = false
		d.Log.Logf(common.SeverityInfo, "Synchronization established at address 0x%x", pkt.Address)
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
	// But NOT for periodic ISYNCs (matches C++ line 360: m_i_sync_pe_ctxt = false)
	contextChanged := !wasSynced || (pkt.ISAValid && pkt.ISA != prevISA) || (pkt.SecureValid && pkt.SecureState != prevSec) || (d.contextID != prevCtx) || (d.vmid != prevVMID)
	if contextChanged && (pkt.ISyncReason != ISyncPeriodic || !wasSynced) {
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
	} else if d.addrValid {
		// Branch address only (no exception) implies an E atom
		// Need to trace from current address to the branch waypoint
		// C++ line 407: only process if m_curr_pe_state.valid is true
		if d.MemAcc != nil {
			_, err := d.traceToWaypoint(common.AtomExecuted)
			if err != nil {
				d.Log.Logf(common.SeverityWarning, "Failed to trace to waypoint: %v", err)
				return d.elements, err
			}
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

	// Note: C++ processAtomRange does NOT check m_curr_pe_state.valid before tracing.
	// It uses the stored address even when valid=false. The valid flag only affects
	// whether we wait for a new address packet after this atom is processed.

	rangeStart := d.currentAddr
	instrCount := uint32(0)
	var lastInstrInfo *common.InstrInfo
	lastExec := atom == common.AtomExecuted

	// Walk instructions until we hit a waypoint (branch, ISB, etc.)
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

		// Check if this is a waypoint (not a normal instruction)
		// ISB is always a waypoint
		// DSB/DMB are waypoints only when configured
		isWaypoint := instrInfo.Type != common.InstrTypeNormal &&
			instrInfo.Type != common.InstrTypeUnknown &&
			(d.DsbDmbWaypoint || instrInfo.Type != common.InstrTypeDSBDMB)

		if isWaypoint {
			// Handle ISB (barrier) - emit range, return false (no atom consumed)
			if instrInfo.Type == common.InstrTypeISB {
				d.currentAddr = nextAddr
				elem := common.GenericTraceElement{
					Type: common.ElemTypeAddrRange,
					AddrRange: common.AddrRange{
						StartAddr:       rangeStart,
						EndAddr:         nextAddr,
						ISA:             d.currentISA,
						NumInstr:        instrCount,
						LastInstrSz:     uint8(instrInfo.Size),
						LastInstrExec:   true, // ISB is always executed
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
				d.Log.Logf(common.SeverityDebug, "  -> ADDR_RANGE (ISB): 0x%X-0x%X (%d instrs)", rangeStart, nextAddr, instrCount)
				return false, nil // ISB does not consume an atom
			}

			// Handle DSB/DMB (barrier) - when configured as waypoint
			if instrInfo.Type == common.InstrTypeDSBDMB && d.DsbDmbWaypoint {
				d.currentAddr = nextAddr
				elem := common.GenericTraceElement{
					Type: common.ElemTypeAddrRange,
					AddrRange: common.AddrRange{
						StartAddr:       rangeStart,
						EndAddr:         nextAddr,
						ISA:             d.currentISA,
						NumInstr:        instrCount,
						LastInstrSz:     uint8(instrInfo.Size),
						LastInstrExec:   true, // DSB/DMB is always executed
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
				d.Log.Logf(common.SeverityDebug, "  -> ADDR_RANGE (DSB/DMB): 0x%X-0x%X (%d instrs)", rangeStart, nextAddr, instrCount)
				return false, nil // DSB/DMB does not consume an atom
			}

			// Handle branches (C++ trc_pkt_decode_ptm.cpp line 549-589)
			// In PTM, ALL branches (conditional or unconditional) consume an atom.
			// The atom value determines whether the branch is taken (E) or not taken (N).
			if instrInfo.IsBranch {
				executed := atom == common.AtomExecuted
				lastExec = executed

				// Determine next address based on branch type and atom value
				// C++ line 551-557: OCSD_INSTR_BR case
				if instrInfo.HasBranchTarget {
					// Direct branch (B, BL, BEQ, etc.)
					if executed {
						// Branch taken - jump to target
						d.currentAddr = instrInfo.BranchTarget
						// Push return address if link branch (C++ line 555-556)
						if instrInfo.IsLink {
							d.retStack = append(d.retStack, nextAddr)
							d.retStackISA = append(d.retStackISA, d.currentISA)
						}
					} else {
						// Branch not taken - continue to next instruction
						d.currentAddr = nextAddr
					}
				} else if instrInfo.Type == common.InstrTypeBranchIndirect {
					// Indirect branch (BX, BLX register) - C++ line 560-588
					if executed {
						// Indirect branch taken - need new address
						d.addrValid = false // C++ line 568
						// fmt.Printf("DEBUG: Indirect branch at 0x%X. IsReturn=%v, RetStackSize=%d, RetStackEnable=%v. Stack=%v\n", d.currentAddr, instrInfo.IsReturn, len(d.retStack), d.RetStackEnable, d.retStack)
						d.Log.Logf(common.SeverityDebug, "Indirect branch at 0x%X. IsReturn=%v, RetStackSize=%d, RetStackEnable=%v", d.currentAddr, instrInfo.IsReturn, len(d.retStack), d.RetStackEnable)
						// Try return stack if enabled and this is a return (C++ line 570-583)
						if d.RetStackEnable && instrInfo.IsReturn && len(d.retStack) > 0 {
							target := d.retStack[len(d.retStack)-1]
							targetISA := d.retStackISA[len(d.retStackISA)-1]
							d.retStack = d.retStack[:len(d.retStack)-1]
							d.retStackISA = d.retStackISA[:len(d.retStackISA)-1]
							d.currentAddr = target
							d.currentISA = targetISA
							d.addrValid = true // C++ line 581
						} else {
							// No return stack - invalid state but continue from next instruction
							// This allows further atoms to be processed (speculative decoding?)
							d.addrValid = false
							// d.currentAddr = nextAddr // Incorrect: taken branch means NOT nextAddr
						}

						// Push to return stack if link branch (C++ line 586-587)
						if instrInfo.IsLink {
							d.retStack = append(d.retStack, nextAddr)
							d.retStackISA = append(d.retStackISA, d.currentISA)
						}
					} else {
						// Indirect branch not taken - continue to next instruction
						d.currentAddr = nextAddr
					}
				} else {
					// Other branch types - continue to next instruction
					d.currentAddr = nextAddr
				}

				// Update ISA if branch was taken and has ISA change
				if executed && instrInfo.NextISAValid {
					d.currentISA = instrInfo.NextISA
				}

				// Emit range (C++ line 591-595)
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

				return true, nil // Branch consumes an atom
			}

			// Other waypoints (should not reach here normally)
			d.currentAddr = nextAddr
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

// processWaypointUpdate handles waypoint update packets
// Waypoint updates trace from current address to the waypoint address using TRACE_TO_ADDR_INCL semantics
// From C++ trc_pkt_decode_ptm.cpp line 453-456
func (d *Decoder) processWaypointUpdate(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	// Check if we have memory access
	if d.MemAcc == nil {
		d.Log.Warning("Cannot process waypoint update without memory accessor")
		return d.elements, nil
	}

	// Waypoint updates only process if we have a valid address
	if !d.addrValid {
		d.Log.Logf(common.SeverityDebug, "Waypoint update at offset %d: no valid address, skipping", pkt.Offset)
		return d.elements, nil
	}

	// Trace to the waypoint address (with inclusive semantics: last instruction is at the waypoint address)
	// C++ trc_pkt_decode_ptm.cpp line 456: TRACE_TO_ADDR_INCL = trace until we execute the instruction AT the address
	err := d.traceToWaypointAddr(pkt.Address, true)
	if err != nil {
		d.Log.Logf(common.SeverityWarning, "Failed to trace to waypoint address 0x%X: %v", pkt.Address, err)
		return d.elements, nil
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
// Timestamps are accumulated - each packet updates only certain bits
func (d *Decoder) processTimestamp(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	// Update accumulated timestamp - only update the bits specified by TSUpdateBits
	if pkt.TSUpdateBits > 0 && pkt.TSUpdateBits <= 64 {
		// Create mask for the bits being updated (low bits)
		var updateMask uint64 = (uint64(1) << pkt.TSUpdateBits) - 1
		// Clear the low bits in current timestamp and set new value
		d.currentTimestamp = (d.currentTimestamp &^ updateMask) | (pkt.Timestamp & updateMask)
	}

	elem := common.GenericTraceElement{
		Type:      common.ElemTypeTimestamp,
		Timestamp: d.currentTimestamp,
	}
	if pkt.CCValid {
		elem.CycleCount = pkt.CycleCount
		elem.HasCycleCount = true
	}
	d.elements = append(d.elements, elem)

	d.Log.Logf(common.SeverityDebug, "Timestamp: 0x%x (update %d bits)", d.currentTimestamp, pkt.TSUpdateBits)

	return d.elements, nil
}

// processContextID handles context ID packets
func (d *Decoder) processContextID(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	// Check if context ID changed
	if pkt.ContextID != d.contextID {
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
	}

	return d.elements, nil
}

// processVMID handles VMID packets
func (d *Decoder) processVMID(pkt Packet) ([]common.GenericTraceElement, error) {
	if !d.syncFound {
		return nil, nil
	}

	// Check if VMID changed
	if pkt.VMID != d.vmid {
		d.vmid = pkt.VMID
		d.Log.Logf(common.SeverityDebug, "VMID updated: 0x%x", d.vmid)

		// Generate PE_CONTEXT element with updated VMID
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
	}

	return d.elements, nil
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

// traceToWaypointAddr traces instructions from current address to a specific waypoint address
// with the given semantics (inclusive or exclusive).
// C++ implementation: trc_pkt_decode_ptm.cpp::traceInstrToWP() and processAtomRange()
// inclusive=true: trace UNTIL we execute the instruction AT the address (TRACE_TO_ADDR_INCL)
// inclusive=false: trace UNTIL we reach the address (TRACE_TO_ADDR_EXCL)
func (d *Decoder) traceToWaypointAddr(waypointAddr uint64, inclusive bool) error {
	if d.MemAcc == nil {
		return fmt.Errorf("memory accessor not set")
	}

	rangeStart := d.currentAddr
	instrCount := uint32(0)
	var lastInstrInfo *common.InstrInfo

	// Walk instructions until we reach the waypoint address
	for step := 0; step < 4096; step++ {
		prevAddr := d.currentAddr

		instrInfo, err := d.decodeInstruction(prevAddr)
		if err != nil {
			// Memory access error - emit ADDR_NACC
			d.Log.Logf(common.SeverityWarning, "Memory access error at 0x%X: %v", prevAddr, err)
			elem := common.GenericTraceElement{
				Type:         common.ElemTypeAddrNacc,
				NaccAddr:     prevAddr,
				NaccMemSpace: d.getSecurityState(),
			}
			d.elements = append(d.elements, elem)
			d.addrValid = false // Need resync
			return nil          // Not fatal
		}

		lastInstrInfo = instrInfo
		instrCount++
		nextAddr := prevAddr + uint64(instrInfo.Size)

		// Check if we've reached the waypoint
		var wpFound bool
		if inclusive {
			// TRACE_TO_ADDR_INCL: stop when we've executed the instruction AT the address
			wpFound = (prevAddr == waypointAddr)
		} else {
			// TRACE_TO_ADDR_EXCL: stop when next instruction is at the address
			wpFound = (nextAddr == waypointAddr)
		}

		if wpFound {
			// Emit the range and return
			elem := common.GenericTraceElement{
				Type: common.ElemTypeAddrRange,
				AddrRange: common.AddrRange{
					StartAddr:       rangeStart,
					EndAddr:         nextAddr,
					ISA:             d.currentISA,
					NumInstr:        instrCount,
					LastInstrSz:     uint8(instrInfo.Size),
					LastInstrExec:   true, // Waypoint update always executes the matched instruction
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
			d.Log.Logf(common.SeverityDebug, "  -> ADDR_RANGE (WP): 0x%X-0x%X (%d instrs)", rangeStart, nextAddr, instrCount)

			d.currentAddr = nextAddr
			return nil
		}

		// Not a waypoint - advance and continue
		d.currentAddr = nextAddr
	}

	// Waypoint address not reached within reasonable distance
	if lastInstrInfo == nil {
		return fmt.Errorf("no instruction decoded starting at 0x%X", rangeStart)
	}

	return fmt.Errorf("waypoint address 0x%X not reached within 4096 instructions starting at 0x%X", waypointAddr, rangeStart)
}
