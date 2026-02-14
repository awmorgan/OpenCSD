package ptm

import (
	"opencsd/internal/codefollower"
	"opencsd/internal/common"
	"opencsd/internal/memacc"
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

	// 3. Decode generated packets
	for _, pkt := range pkts {
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

	// Emit Trace On
	d.push(&common.TraceElement{
		ElemType: common.ElemTraceOn,
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
			d.push(&common.TraceElement{
				ElemType: common.ElemAddrNacc,
				StAddr:   d.follower.NaccAddr,
			})
			d.addrValid = false
			return nil
		}

		// Emit Range Element
		elem := &common.TraceElement{
			ElemType: common.ElemInstrRange,
			StAddr:   d.follower.StRangeAddr,
			EnAddr:   d.follower.EnRangeAddr,
			ISA:      d.follower.Info.ISA,
		}
		// Last atom in packet gets the cycle count if present
		if i == count-1 && pkt.ccValid {
			elem.CycleCount = pkt.cycleCount
			elem.HasCC = true
		}
		d.push(elem)

		// Prepare for next atom
		if d.follower.NextValid {
			d.instrAddr = d.follower.NextAddr
			d.isa = d.follower.Info.NextISA
		} else {
			d.addrValid = false
			// If indirect branch executed, we wait for next BranchAddress packet
			return nil
		}
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
				ElemType: common.ElemInstrRange,
				StAddr:   d.follower.StRangeAddr,
				EnAddr:   d.follower.EnRangeAddr,
				ISA:      d.follower.Info.ISA,
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
	})
}

func (d *PtmDecoder) push(elem *common.TraceElement) {
	d.sink.TraceElemIn(0, 0, elem)
}
