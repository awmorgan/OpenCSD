package ptm

import (
	"opencsd/internal/common"
)

// PtmDecoder converts PTM Packets into Generic Trace Elements.
// It tracks the state required to generate context and range elements.
type PtmDecoder struct {
	sink common.GenElemIn

	// Internal State tracking
	peContext common.PeContext
}

func NewPtmDecoder(sink common.GenElemIn) *PtmDecoder {
	return &PtmDecoder{
		sink: sink,
		peContext: common.PeContext{
			SecurityLevel:  common.SecSecure, // Default assumption, updated by packets
			ExceptionLevel: common.EL0,       // Default
		},
	}
}

// DecodePacket takes a raw PTM packet and generates generic elements.
func (d *PtmDecoder) DecodePacket(pkt *PtmPacket) error {
	// 1. Check for Context Updates
	if pkt.context.updated {
		d.updateContext(pkt)
		// If context changed, we emit a Context Element
		elem := &common.TraceElement{
			ElemType: common.ElemPeContext,
			Context:  d.peContext,
		}
		d.push(elem)
	}

	// 2. Handle Packet Types
	switch pkt.typeID {
	case ptmPktAtom:
		// Atoms indicate instruction execution.
		// In full decode, this would trigger walking the memory image.
		// For now, we might just emit the atom info or an "Instruction Range" placeholder.
		// (Full instruction decoding requires the `memacc` layer attached here later)

	case ptmPktExceptionRet:
		d.push(&common.TraceElement{ElemType: common.ElemExceptionRet})

	case ptmPktBranchAddress:
		// Branch addr + Atom usually = Instruction Range.
		// For now, we update state.

	case ptmPktTimestamp:
		d.push(&common.TraceElement{
			ElemType:  common.ElemTimestamp,
			Timestamp: pkt.timestamp,
			HasTS:     true,
		})
	}

	return nil
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
	// EL is harder to track in pure PTM without external cues,
	// often derived from exception packets.
}

func (d *PtmDecoder) push(elem *common.TraceElement) {
	// In a real pipeline, we pass index/chanID. 0 for now.
	d.sink.TraceElemIn(0, 0, elem)
}
