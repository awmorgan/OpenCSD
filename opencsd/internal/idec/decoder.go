package idec

import (
	"opencsd/internal/ocsd"
)

// Decoder implements the ocsd.InstrDecode interface.
type Decoder struct {
	aa64ErrBadOpcode bool
}

func NewDecoder() *Decoder {
	return &Decoder{
		aa64ErrBadOpcode: false,
	}
}

func (d *Decoder) SetAA64ErrOnBadOpcode(bSet bool) {
	d.aa64ErrBadOpcode = bSet
}

func (d *Decoder) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	info := &DecodeInfo{
		InstrSubType: ocsd.SInstrNone,
		ArchVersion:  instrInfo.PeType.Arch,
	}

	var err ocsd.Err = ocsd.OK

	switch instrInfo.Isa {
	case ocsd.ISAArm:
		err = d.decodeA32(instrInfo, info)
	case ocsd.ISAThumb2:
		err = d.decodeT32(instrInfo, info)
	case ocsd.ISAAArch64:
		err = d.decodeA64(instrInfo, info)
	case ocsd.ISATee, ocsd.ISAJazelle:
		fallthrough
	default:
		// unsupported ISA
		err = ocsd.ErrUnsupportedISA
	}

	instrInfo.SubType = info.InstrSubType
	return err
}

func (d *Decoder) decodeA32(instrInfo *ocsd.InstrInfo, info *DecodeInfo) ocsd.Err {
	var branchAddr uint32
	var barrier ArmBarrierT

	instrInfo.InstrSize = 4           // instruction size A32
	instrInfo.Type = ocsd.InstrOther  // default type
	instrInfo.NextIsa = instrInfo.Isa // assume same ISA
	instrInfo.IsLink = 0
	instrInfo.ThumbItConditions = 0 // not thumb

	if InstARMIsIndirectBranch(instrInfo.Opcode, info) {
		instrInfo.Type = ocsd.InstrBrIndirect
		if InstARMIsBranchAndLink(instrInfo.Opcode, info) {
			instrInfo.IsLink = 1
		} else {
			instrInfo.IsLink = 0
		}
	} else if InstARMIsDirectBranch(instrInfo.Opcode) {
		InstARMBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode, &branchAddr)
		instrInfo.Type = ocsd.InstrBr
		if (branchAddr & 0x1) != 0 {
			instrInfo.NextIsa = ocsd.ISAThumb2
			branchAddr &= ^uint32(0x1)
		}
		instrInfo.BranchAddr = ocsd.VAddr(branchAddr)
		if InstARMIsBranchAndLink(instrInfo.Opcode, info) {
			instrInfo.IsLink = 1
		} else {
			instrInfo.IsLink = 0
		}
	} else if barrier = InstARMBarrier(instrInfo.Opcode); barrier != ArmBarrierNone {
		switch barrier {
		case ArmBarrierIsb:
			instrInfo.Type = ocsd.InstrIsb
		case ArmBarrierDsb, ArmBarrierDmb:
			if instrInfo.DsbDmbWaypoints != 0 {
				instrInfo.Type = ocsd.InstrDsbDmb
			}
		}
	} else if instrInfo.WfiWfeBranch != 0 {
		if InstARMWfiWfe(instrInfo.Opcode) {
			instrInfo.Type = ocsd.InstrWfiWfe
		}
	}

	if InstARMIsConditional(instrInfo.Opcode) {
		instrInfo.IsConditional = 1
	} else {
		instrInfo.IsConditional = 0
	}

	return ocsd.OK
}

func (d *Decoder) decodeA64(instrInfo *ocsd.InstrInfo, info *DecodeInfo) ocsd.Err {
	var branchAddr uint64
	var barrier ArmBarrierT

	instrInfo.InstrSize = 4           // default address update
	instrInfo.Type = ocsd.InstrOther  // default type
	instrInfo.NextIsa = instrInfo.Isa // assume same ISA
	instrInfo.IsLink = 0
	instrInfo.ThumbItConditions = 0

	// check for invalid opcode - top 16 bits cannot be 0x0000.
	if d.aa64ErrBadOpcode && (instrInfo.Opcode&0xFFFF0000) == 0 {
		return ocsd.ErrInvalidOpcode
	}

	if InstA64IsIndirectBranchLink(instrInfo.Opcode, &instrInfo.IsLink, info) {
		instrInfo.Type = ocsd.InstrBrIndirect
	} else if InstA64IsDirectBranchLink(instrInfo.Opcode, &instrInfo.IsLink, info) {
		InstA64BranchDestination(uint64(instrInfo.InstrAddr), instrInfo.Opcode, &branchAddr)
		instrInfo.Type = ocsd.InstrBr
		instrInfo.BranchAddr = ocsd.VAddr(branchAddr)
	} else if barrier = InstA64Barrier(instrInfo.Opcode); barrier != ArmBarrierNone {
		switch barrier {
		case ArmBarrierIsb:
			instrInfo.Type = ocsd.InstrIsb
		case ArmBarrierDsb, ArmBarrierDmb:
			if instrInfo.DsbDmbWaypoints != 0 {
				instrInfo.Type = ocsd.InstrDsbDmb
			}
		}
	} else if instrInfo.WfiWfeBranch != 0 && InstA64WfiWfe(instrInfo.Opcode, info) {
		instrInfo.Type = ocsd.InstrWfiWfe
	} else if ocsd.IsArchMinVer(info.ArchVersion, ocsd.ArchAA64) {
		if InstA64Tstart(instrInfo.Opcode) {
			instrInfo.Type = ocsd.InstrTstart
		}
	}

	if InstA64IsConditional(instrInfo.Opcode) {
		instrInfo.IsConditional = 1
	} else {
		instrInfo.IsConditional = 0
	}

	return ocsd.OK
}

func (d *Decoder) decodeT32(instrInfo *ocsd.InstrInfo, info *DecodeInfo) ocsd.Err {
	var branchAddr uint32
	var barrier ArmBarrierT

	// need to align the 32 bit opcode as 2 16 bit, with LS 16 as in top 16 bit of
	// 32 bit word - T2 routines assume 16 bit in top 16 bit of 32 bit opcode.
	opTemp := (instrInfo.Opcode >> 16) & 0xFFFF
	opTemp |= (instrInfo.Opcode & 0xFFFF) << 16
	instrInfo.Opcode = opTemp

	if IsWideThumb(uint16(instrInfo.Opcode >> 16)) {
		instrInfo.InstrSize = 4
	} else {
		instrInfo.InstrSize = 2
	}
	instrInfo.Type = ocsd.InstrOther  // default type
	instrInfo.NextIsa = instrInfo.Isa // assume same ISA
	instrInfo.IsLink = 0
	instrInfo.IsConditional = 0

	if InstThumbIsDirectBranchLink(instrInfo.Opcode, &instrInfo.IsLink, &instrInfo.IsConditional, info) {
		InstThumbBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode, &branchAddr)
		instrInfo.Type = ocsd.InstrBr
		instrInfo.BranchAddr = ocsd.VAddr(branchAddr & ^uint32(0x1))
		if (branchAddr & 0x1) == 0 {
			instrInfo.NextIsa = ocsd.ISAArm
		}
	} else if InstThumbIsIndirectBranchLink(instrInfo.Opcode, &instrInfo.IsLink, info) {
		instrInfo.Type = ocsd.InstrBrIndirect
	} else if barrier = InstThumbBarrier(instrInfo.Opcode); barrier != ArmBarrierNone {
		switch barrier {
		case ArmBarrierIsb:
			instrInfo.Type = ocsd.InstrIsb
		case ArmBarrierDsb, ArmBarrierDmb:
			if instrInfo.DsbDmbWaypoints != 0 {
				instrInfo.Type = ocsd.InstrDsbDmb
			}
		}
	} else if instrInfo.WfiWfeBranch != 0 {
		if InstThumbWfiWfe(instrInfo.Opcode) {
			instrInfo.Type = ocsd.InstrWfiWfe
		}
	}

	if InstThumbIsConditional(instrInfo.Opcode) {
		instrInfo.IsConditional = 1
	}

	if instrInfo.TrackItBlock != 0 {
		if instrInfo.ThumbItConditions == 0 {
			// if the type is not something else we are interested in, check for IT instruction
			if instrInfo.Type == ocsd.InstrOther {
				instrInfo.ThumbItConditions = uint8(InstThumbIsIT(instrInfo.Opcode))
			}
		} else {
			instrInfo.IsConditional = 1
			instrInfo.ThumbItConditions--
		}
	}

	return ocsd.OK
}
