package ptm

import (
	"opencsd/internal/codefollower"
	"opencsd/internal/common"
	"opencsd/internal/memacc"
	"opencsd/internal/printers"
)

// PtmDecoder converts PTM Packets into Generic Trace Elements.
type PtmDecoder struct {
	sink     common.GenElemIn
	mapper   *memacc.Mapper
	follower *codefollower.CodeFollower
	retStack *common.ReturnStack // Added Return Stack instance
	pktProc  *PktProcessor

	// Internal State tracking
	peContext common.PeContext
	state     int
	needIsync bool

	// Current Execution State
	instrAddr uint64
	isa       common.Isa
	addrValid bool

	// current packet index (used when emitting elements)
	currentPktIndex int64
}

const (
	dcdStateNoSync = iota
	dcdStateWaitSync
	dcdStateWaitIsync
	dcdStateDecodePkts
)

func NewPtmDecoder(sink common.GenElemIn, mapper *memacc.Mapper) *PtmDecoder {
	return &PtmDecoder{
		sink:      sink,
		mapper:    mapper,
		follower:  codefollower.NewCodeFollower(mapper),
		retStack:  common.NewReturnStack(), // Init Stack
		pktProc:   NewPktProcessor(),
		state:     dcdStateNoSync,
		needIsync: true,
		peContext: common.PeContext{
			SecurityLevel:  common.SecSecure,
			ExceptionLevel: common.EL0,
		},
	}
}

// TraceDataIn implements common.TrcDataIn
func (d *PtmDecoder) TraceDataIn(op common.DataPathOp, index int64, data []byte) (common.DataPathResp, int, error) {
	if op == common.OpEOT {
		// Flush or reset if needed
		return common.RespCont, 0, nil
	}

	// 1. Push data into Packet Processor
	d.pktProc.AddData(data, index)

	// 2. Pump the processor
	pkts, err := d.pktProc.ProcessPackets()
	if err != nil {
		return common.RespFatal, 0, err
	}

	// 3. Emit packet-level dump lines (raw bytes) then decode generated packets
	//    This reproduces the C++ trc_pkt_lister output where each packet's
	//    raw bytes + textual packet description are printed before the
	//    generic trace elements that follow.
	if printer, ok := d.sink.(*printers.PktPrinter); ok {
		for _, pkt := range pkts {
			printer.PrintPacketRaw(pkt.Index, 0, pkt.RawBytes, pkt.ToString())
		}
	}

	for _, pkt := range pkts {
		// record current packet index so pushed elements use the same index
		d.currentPktIndex = int64(pkt.Index)
		if err := d.DecodePacket(&pkt); err != nil {
			return common.RespFatal, 0, err
		}
	}

	return common.RespCont, len(data), nil
}

// DecodePacket takes a raw PTM packet and generates generic elements.
func (d *PtmDecoder) DecodePacket(pkt *PtmPacket) error {
	switch d.state {
	case dcdStateNoSync:
		d.push(&common.TraceElement{ElemType: common.ElemNoSync})
		if pkt.typeID == ptmPktAsync {
			d.state = dcdStateWaitIsync
		} else {
			d.state = dcdStateWaitSync
		}
	case dcdStateWaitSync:
		if pkt.typeID == ptmPktAsync {
			d.state = dcdStateWaitIsync
		}
	case dcdStateWaitIsync:
		if pkt.typeID == ptmPktISync {
			d.state = dcdStateDecodePkts
			return d.processIsync(pkt)
		}
	case dcdStateDecodePkts:
		return d.decodePacketBody(pkt)
	}
	return nil
}

func (d *PtmDecoder) decodePacketBody(pkt *PtmPacket) error {
	switch pkt.typeID {
	case ptmPktAsync:
		// Reset to wait Isync? Usually Async in stream just means alignment
	case ptmPktISync:
		return d.processIsync(pkt)
	case ptmPktAtom:
		return d.processAtom(pkt)
	case ptmPktBranchAddress:
		return d.processBranch(pkt)
	case ptmPktTimestamp:
		d.push(&common.TraceElement{
			ElemType:   common.ElemTimestamp,
			Timestamp:  pkt.timestamp,
			HasTS:      true,
			CycleCount: pkt.cycleCount,
			HasCC:      pkt.ccValid,
		})
	case ptmPktExceptionRet:
		d.push(&common.TraceElement{ElemType: common.ElemExceptionRet})
	case ptmPktContextID:
		if pkt.context.updatedC {
			d.peContext.ContextID = pkt.context.ctxtID
			d.pushContext()
		}
	case ptmPktVMID:
		if pkt.context.updatedV {
			d.peContext.VMID = uint32(pkt.context.vmid)
			d.pushContext()
		}
	}
	return nil
}

func (d *PtmDecoder) processIsync(pkt *PtmPacket) error {
	d.instrAddr = uint64(pkt.addr.val)
	d.isa = pkt.currISA
	d.addrValid = true

	d.updateContext(pkt)
	d.pushContext()

	// Emit Trace On (carry reason from packet iSync)
	traceOnReason := 0
	switch pkt.iSync {
	case iSyncRestartOverflow:
		traceOnReason = 1
	case iSyncDebugExit:
		traceOnReason = 2
	default:
		traceOnReason = 0
	}
	d.push(&common.TraceElement{
		ElemType:      common.ElemTraceOn,
		TraceOnReason: traceOnReason,
	})

	// Flush Return Stack on Sync
	d.retStack.Flush()

	return nil
}

func (d *PtmDecoder) processAtom(pkt *PtmPacket) error {
	if !d.addrValid {
		// Error: Atom without address
		return nil
	}

	d.setupFollower()

	bits := pkt.atom.enBits
	count := int(pkt.atom.num)

	// Iterate bits from LSB to MSB (as per PTM spec)
	// enBits: 1 = E, 0 = N
	var merged *common.TraceElement
	for i := 0; i < count; i++ {
		atomBit := bits & 1
		bits >>= 1

		atomVal := common.AtomN
		if atomBit == 1 {
			atomVal = common.AtomE
		}

		// Follow the code!
		err := d.follower.FollowSingleAtom(d.instrAddr, atomVal, d.isa)
		if err != nil {
			return err
		}

		// Handle Memory Access Failures
		if d.follower.NaccPending {
			// Flush any pending merged range before reporting NACC
			if merged != nil {
				d.push(merged)
				merged = nil
			}
			d.push(&common.TraceElement{
				ElemType: common.ElemAddrNacc,
				StAddr:   d.follower.NaccAddr,
			})
			d.addrValid = false
			return nil
		}

		// Build a candidate range for this atom
		candStart := d.follower.StRangeAddr
		candEnd := d.follower.EnRangeAddr
		candISA := d.follower.Info.ISA
		candLast := d.follower.Info
		candExec := (atomVal == common.AtomE)

		if merged == nil {
			merged = &common.TraceElement{
				ElemType:      common.ElemInstrRange,
				StAddr:        candStart,
				EnAddr:        candEnd,
				ISA:           candISA,
				NumInstr:      1,
				LastInstr:     candLast,
				LastInstrExec: candExec,
			}
		} else {
			// Merge only if contiguous, same ISA and same exec status for last instr
			if merged.EnAddr == candStart && merged.ISA == candISA && merged.LastInstrExec == candExec {
				merged.EnAddr = candEnd
				merged.NumInstr++
				merged.LastInstr = candLast
				merged.LastInstrExec = candExec
			} else {
				// flush previous merged and start a new one
				d.push(merged)
				merged = &common.TraceElement{
					ElemType:      common.ElemInstrRange,
					StAddr:        candStart,
					EnAddr:        candEnd,
					ISA:           candISA,
					NumInstr:      1,
					LastInstr:     candLast,
					LastInstrExec: candExec,
				}
			}
		}

		// If this is the last atom in the packet, attach cycle count to the merged range
		if i == count-1 && pkt.ccValid {
			merged.CycleCount = pkt.cycleCount
			merged.HasCC = true
		}

		// Prepare for next atom
		if d.follower.NextValid {
			d.instrAddr = d.follower.NextAddr
			d.isa = d.follower.Info.NextISA
		} else {
			// push any pending merged range
			if merged != nil {
				d.push(merged)
				merged = nil
			}
			d.addrValid = false
			// If indirect branch executed, we wait for next BranchAddress packet
			return nil
		}
	}

	// push any remaining merged range
	if merged != nil {
		d.push(merged)
		merged = nil
	}
	return nil
}

func (d *PtmDecoder) processBranch(pkt *PtmPacket) error {
	// 1. Handle Exception vs Normal Branch
	if pkt.exception.present {
		// === Exception Packet ===
		elem := &common.TraceElement{
			ElemType: common.ElemException,
			ExcepID:  uint32(pkt.exception.number),
		}
		// If we were executing, capture the preferred return address
		if d.addrValid {
			elem.StAddr = d.instrAddr
			elem.EnAddr = d.instrAddr
		}
		// Exceptions can carry Cycle Counts
		if pkt.ccValid {
			elem.CycleCount = pkt.cycleCount
			elem.HasCC = true
		}
		d.push(elem)

	} else if d.addrValid {
		// === Normal Branch Address Packet ===
		// This implies an "E" atom for the instruction that caused the branch.
		// We must "follow" this instruction to generate the proper instruction range packet
		// BEFORE we switch to the new address.

		d.setupFollower() // Ensure follower has current context/stack

		// "Execute" the branch instruction (Atom E)
		err := d.follower.FollowSingleAtom(d.instrAddr, common.AtomE, d.isa)
		if err != nil {
			return err
		}

		// Check for Memory Access Faults during decode
		if d.follower.NaccPending {
			d.push(&common.TraceElement{
				ElemType: common.ElemAddrNacc,
				StAddr:   d.follower.NaccAddr,
			})
			d.addrValid = false
			// We fall through because the Branch Packet provides a new valid address,
			// allowing us to recover immediately.
		} else {
			// Emit the instruction range for this branch instruction
			elem := &common.TraceElement{
				ElemType:      common.ElemInstrRange,
				StAddr:        d.follower.StRangeAddr,
				EnAddr:        d.follower.EnRangeAddr,
				ISA:           d.follower.Info.ISA,
				NumInstr:      1,
				LastInstr:     d.follower.Info,
				LastInstrExec: true,
			}

			// If the packet has a cycle count, it applies to this executed branch
			if pkt.ccValid {
				elem.CycleCount = pkt.cycleCount
				elem.HasCC = true
			}
			d.push(elem)
		}
	}

	// 2. Update Decoder State to the new address provided by the packet
	// This overrides whatever the follower calculated as "NextAddr" because
	// the packet is the authoritative source of truth.
	d.instrAddr = uint64(pkt.addr.val)
	d.isa = pkt.currISA
	d.addrValid = true

	// Update context (Security, VMID, etc.) if the packet contains changes
	d.updateContext(pkt)

	return nil
}

func (d *PtmDecoder) setupFollower() {
	memSpace := memacc.MemSpaceEL1S // Default/Example
	if d.peContext.SecurityLevel == common.SecNonSecure {
		memSpace = memacc.MemSpaceEL1N // Simplified mapping
	}
	// Pass the return stack to the follower
	d.follower.Setup(0, memSpace, d.retStack)
}

func (d *PtmDecoder) updateContext(pkt *PtmPacket) {
	if pkt.context.updatedC {
		d.peContext.ContextID = pkt.context.ctxtID
	}
	if pkt.context.updatedV {
		d.peContext.VMID = uint32(pkt.context.vmid)
	}
	if pkt.context.currNS {
		d.peContext.SecurityLevel = common.SecNonSecure
	} else {
		d.peContext.SecurityLevel = common.SecSecure
	}
}

func (d *PtmDecoder) pushContext() {
	d.push(&common.TraceElement{
		ElemType: common.ElemPeContext,
		Context:  d.peContext,
		ISA:      d.isa,
	})
}

func (d *PtmDecoder) push(elem *common.TraceElement) {
	// Use the packet index recorded when processing the packet and the
	// canonical channel ID 2 for generic trace elements (matches C++ lister)
	d.sink.TraceElemIn(d.currentPktIndex, 2, elem)
}
