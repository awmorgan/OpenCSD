package idec

import "opencsd/internal/ocsd"

// Decoder implements the ocsd.InstrDecode interface.
type Decoder struct {
	aa64ErrBadOpcode bool
}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) SetAA64ErrOnBadOpcode(bSet bool) {
	d.aa64ErrBadOpcode = bSet
}

func (d *Decoder) DecodeInstruction(instrInfo *ocsd.InstrInfo) error {
	info := DecodeInfo{
		InstrSubType: ocsd.SInstrNone,
		ArchVersion:  instrInfo.PeType.Arch,
	}

	var err error
	switch instrInfo.ISA {
	case ocsd.ISAArm:
		err = d.decodeA32(instrInfo, &info)
	case ocsd.ISAThumb2:
		err = d.decodeT32(instrInfo, &info)
	case ocsd.ISAAArch64:
		err = d.decodeA64(instrInfo, &info)
	default:
		err = ocsd.ErrUnsupportedISA
	}

	instrInfo.Subtype = info.InstrSubType
	return err
}

func resetInstrInfo(instrInfo *ocsd.InstrInfo) {
	instrInfo.Type = ocsd.InstrOther
	instrInfo.NextISA = instrInfo.ISA
	instrInfo.IsLink = 0
	instrInfo.IsConditional = 0
}

func setBool(dst *uint8, value bool) {
	if value {
		*dst = 1
		return
	}
	*dst = 0
}

func applyBarrier(instrInfo *ocsd.InstrInfo, barrier ArmBarrierT) bool {
	switch barrier {
	case ArmBarrierIsb:
		instrInfo.Type = ocsd.InstrIsb
		return true
	case ArmBarrierDsb, ArmBarrierDmb:
		if instrInfo.DsbDmbWaypoints != 0 {
			instrInfo.Type = ocsd.InstrDsbDmb
		}
		return true
	default:
		return false
	}
}

func canonicalThumbOpcode(opcode uint32) uint32 {
	return (opcode>>16)&0xFFFF | (opcode&0xFFFF)<<16
}

func setThumbInstrSize(instrInfo *ocsd.InstrInfo) {
	if IsWideThumb(uint16(instrInfo.Opcode >> 16)) {
		instrInfo.InstrSize = 4
		return
	}
	instrInfo.InstrSize = 2
}

func (d *Decoder) decodeA32(instrInfo *ocsd.InstrInfo, info *DecodeInfo) error {
	resetInstrInfo(instrInfo)
	instrInfo.InstrSize = 4
	instrInfo.ThumbItConditions = 0 // not Thumb

	switch {
	case InstARMIsIndirectBranch(instrInfo.Opcode, info):
		instrInfo.Type = ocsd.InstrBrIndirect
		setBool(&instrInfo.IsLink, InstARMIsBranchAndLink(instrInfo.Opcode, info))

	case InstARMIsDirectBranch(instrInfo.Opcode):
		branchAddr, _ := InstARMBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode)
		instrInfo.Type = ocsd.InstrBr
		if branchAddr&0x1 != 0 {
			instrInfo.NextISA = ocsd.ISAThumb2
			branchAddr &^= 0x1
		}
		instrInfo.BranchAddr = ocsd.VAddr(branchAddr)
		setBool(&instrInfo.IsLink, InstARMIsBranchAndLink(instrInfo.Opcode, info))

	case applyBarrier(instrInfo, InstARMBarrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && InstARMWfiWfe(instrInfo.Opcode):
		instrInfo.Type = ocsd.InstrWfiWfe
	}

	setBool(&instrInfo.IsConditional, InstARMIsConditional(instrInfo.Opcode))
	return nil
}

func (d *Decoder) decodeA64(instrInfo *ocsd.InstrInfo, info *DecodeInfo) error {
	resetInstrInfo(instrInfo)
	instrInfo.InstrSize = 4
	instrInfo.ThumbItConditions = 0

	// Top 16 bits cannot be 0x0000 when strict A64 opcode checks are enabled.
	if d.aa64ErrBadOpcode && instrInfo.Opcode&0xFFFF0000 == 0 {
		return ocsd.ErrInvalidOpcode
	}

	switch {
	case decodeA64IndirectBranch(instrInfo, info):
	case decodeA64DirectBranch(instrInfo, info):
	case applyBarrier(instrInfo, InstA64Barrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && InstA64WfiWfe(instrInfo.Opcode, info):
		instrInfo.Type = ocsd.InstrWfiWfe
	case ocsd.IsArchMinVer(info.ArchVersion, ocsd.ArchAA64) && InstA64Tstart(instrInfo.Opcode):
		instrInfo.Type = ocsd.InstrTstart
	}

	setBool(&instrInfo.IsConditional, InstA64IsConditional(instrInfo.Opcode))
	return nil
}

func decodeA64IndirectBranch(instrInfo *ocsd.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink := InstA64IsIndirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}
	instrInfo.Type = ocsd.InstrBrIndirect
	setBool(&instrInfo.IsLink, isLink)
	return true
}

func decodeA64DirectBranch(instrInfo *ocsd.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink := InstA64IsDirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}

	var branchAddr uint64
	InstA64BranchDestination(uint64(instrInfo.InstrAddr), instrInfo.Opcode, &branchAddr)
	instrInfo.Type = ocsd.InstrBr
	instrInfo.BranchAddr = ocsd.VAddr(branchAddr)
	setBool(&instrInfo.IsLink, isLink)
	return true
}

func (d *Decoder) decodeT32(instrInfo *ocsd.InstrInfo, info *DecodeInfo) error {
	instrInfo.Opcode = canonicalThumbOpcode(instrInfo.Opcode)
	resetInstrInfo(instrInfo)
	setThumbInstrSize(instrInfo)

	switch {
	case decodeT32DirectBranch(instrInfo, info):
	case decodeT32IndirectBranch(instrInfo, info):
	case applyBarrier(instrInfo, InstThumbBarrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && InstThumbWfiWfe(instrInfo.Opcode):
		instrInfo.Type = ocsd.InstrWfiWfe
	}

	if InstThumbIsConditional(instrInfo.Opcode) {
		instrInfo.IsConditional = 1
	}
	updateThumbITBlock(instrInfo)
	return nil
}

func decodeT32DirectBranch(instrInfo *ocsd.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink, isCond := InstThumbIsDirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}

	branchAddr, _ := InstThumbBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode)
	instrInfo.Type = ocsd.InstrBr
	instrInfo.BranchAddr = ocsd.VAddr(branchAddr &^ 0x1)
	setBool(&instrInfo.IsLink, isLink)
	setBool(&instrInfo.IsConditional, isCond)
	if branchAddr&0x1 == 0 {
		instrInfo.NextISA = ocsd.ISAArm
	}
	return true
}

func decodeT32IndirectBranch(instrInfo *ocsd.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink := InstThumbIsIndirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}
	instrInfo.Type = ocsd.InstrBrIndirect
	setBool(&instrInfo.IsLink, isLink)
	return true
}

func updateThumbITBlock(instrInfo *ocsd.InstrInfo) {
	if instrInfo.TrackItBlock == 0 {
		return
	}
	if instrInfo.ThumbItConditions > 0 {
		instrInfo.IsConditional = 1
		instrInfo.ThumbItConditions--
		return
	}
	if instrInfo.Type == ocsd.InstrOther {
		instrInfo.ThumbItConditions = uint8(InstThumbIsIT(instrInfo.Opcode))
	}
}
