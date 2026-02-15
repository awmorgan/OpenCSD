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
	retStack *common.ReturnStack
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
		retStack:  common.NewReturnStack(),
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
		d.push(&common.TraceElement{ElemType: common.ElemEOTrace})
		return common.RespCont, 0, nil
	}

	// 1. Push data into Packet Processor
	d.pktProc.AddData(data, index)

	// 2. Pump the processor
	pkts, err := d.pktProc.ProcessPackets()
	if err != nil {
		return common.RespFatal, 0, err
	}

	// 3. Emit packet-level dump lines (raw bytes) first
	if printer, ok := d.sink.(*printers.PktPrinter); ok {
		for _, pkt := range pkts {
			printer.PrintPacketRaw(pkt.Index, 0, pkt.RawBytes, pkt.ToString())
		}
	}

	// 4. Decode generated packets
	for _, pkt := range pkts {
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
		d.state = dcdStateWaitIsync
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

	d.retStack.Flush()
	return nil
}

func (d *PtmDecoder) processAtom(pkt *PtmPacket) error {
	// If we don't have a valid address, we can't process atoms.
	if !d.addrValid {
		return nil
	}

	d.setupFollower()

	bits := pkt.atom.enBits
	count := int(pkt.atom.num)

	// Iterate bits from LSB to MSB
	for i := 0; i < count; i++ {
		// IMPORTANT: If we lost the address (e.g. indirect branch failed),
		// we MUST stop processing the remaining atoms in this packet.
		// This matches C++ m_atoms.clearAll() behavior.
		if !d.addrValid {
			break
		}

		atomBit := bits & 1
		bits >>= 1

		atomVal := common.AtomN
		if atomBit == 1 {
			atomVal = common.AtomE
		}

		err := d.processAtomRange(atomVal)
		if err != nil {
			return err
		}

		// Note: Cycle count handling for atoms is omitted for brevity,
		// but typically attaches to the last atom's range.
	}
	return nil
}

func (d *PtmDecoder) processAtomRange(atomVal common.AtomVal) error {
	// 1. Walk code until Waypoint
	err := d.follower.TraceToWaypoint(d.instrAddr, d.isa)
	if err != nil {
		return err
	}

	// 2. Check for NACC (Memory Access Error)
	if d.follower.NaccPending {
		d.push(&common.TraceElement{
			ElemType: common.ElemAddrNacc,
			StAddr:   d.follower.NaccAddr,
			Context:  d.peContext,
		})
		d.addrValid = false
		return nil
	}

	// 3. Emit Range Element
	elem := &common.TraceElement{
		ElemType:      common.ElemInstrRange,
		StAddr:        d.follower.StRangeAddr,
		EnAddr:        d.follower.EnRangeAddr,
		ISA:           d.follower.Info.ISA,
		NumInstr:      int(d.follower.InstrCount), // Correct instruction count
		LastInstr:     d.follower.Info,
		LastInstrExec: (atomVal == common.AtomE),
	}
	d.push(elem)

	// 4. Calculate Next Address
	// Default is sequential execution (falling through to EnRangeAddr)
	nextAddr := d.follower.EnRangeAddr
	d.addrValid = true

	// Handle Waypoint Logic (Branching)
	switch d.follower.Info.Type {
	case common.InstrTypeBranch:
		if atomVal == common.AtomE {
			nextAddr = d.follower.Info.BranchAddr
			// Handle Link (Push to stack)
			if d.follower.Info.IsLink {
				d.retStack.Push(d.follower.EnRangeAddr, d.follower.Info.ISA)
			}
		}

	case common.InstrTypeIndirect:
		if atomVal == common.AtomE {
			// Executed Indirect Branch -> We need a target address.
			// Try Return Stack first.
			d.addrValid = false // Assume invalid unless stack saves us

			if d.retStack != nil {
				if addr, isa, ok := d.retStack.Pop(); ok {
					nextAddr = addr
					d.follower.Info.NextISA = isa
					d.addrValid = true
				}
			}

			// Handle Link (Push to stack) even if indirect (e.g. BLX <reg>)
			if d.follower.Info.IsLink {
				d.retStack.Push(d.follower.EnRangeAddr, d.follower.Info.ISA)
			}
		}
		// If AtomN (Not Executed), we just fall through to sequential (nextAddr), which is valid.
	}

	// 5. Update Decoder State
	if d.addrValid {
		d.instrAddr = nextAddr
		// Update ISA if transition occurred
		if d.follower.Info.NextISA != d.follower.Info.ISA {
			d.isa = d.follower.Info.NextISA
		}
	}

	return nil
}

func (d *PtmDecoder) processBranch(pkt *PtmPacket) error {
	if pkt.exception.present {
		// === Exception Packet ===
		elem := &common.TraceElement{
			ElemType: common.ElemException,
			ExcepID:  uint32(pkt.exception.number),
		}
		if d.addrValid {
			elem.StAddr = d.instrAddr
			elem.EnAddr = d.instrAddr
			elem.ExcepRetAddr = 1 // Flag that we have a valid return address
		}
		if pkt.ccValid {
			elem.CycleCount = pkt.cycleCount
			elem.HasCC = true
		}
		d.push(elem)
	} else if d.addrValid {
		// === Normal Branch Address Packet ===
		// This implies the current instruction is a branch that was executed.
		// We must "consume" it as an Atom E before switching address.
		d.setupFollower()
		err := d.processAtomRange(common.AtomE)
		if err != nil {
			return err
		}
	}

	// Update Decoder State to new address
	d.instrAddr = uint64(pkt.addr.val)
	d.isa = pkt.currISA
	d.addrValid = true
	d.updateContext(pkt)

	return nil
}

func (d *PtmDecoder) setupFollower() {
	memSpace := memacc.MemSpaceEL1S
	if d.peContext.SecurityLevel == common.SecNonSecure {
		memSpace = memacc.MemSpaceEL1N
	}
	d.follower.Setup(0, memSpace)
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
	d.sink.TraceElemIn(d.currentPktIndex, 2, elem)
}
