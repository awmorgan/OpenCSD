package idec

import (
	"opencsd/internal/common"
)

type DecodeInfo struct {
	ArchVersion  string
	InstrSubType int
}

const (
	SubTypeNone         = 0
	SubTypeBrLink       = 1
	SubTypeV7ImpliedRet = 2
	SubTypeV8Ret        = 3
	SubTypeV8Eret       = 4
)

func SignExtend32(val uint32, bits int) int32 {
	shift := 32 - bits
	return int32(val<<uint(shift)) >> uint(shift)
}

func DecodeInstruction(instrInfo *common.InstrInfo, currentISA common.Isa) error {
	info := &DecodeInfo{InstrSubType: SubTypeNone}

	instrInfo.Type = common.InstrTypeOther
	instrInfo.IsLink = false
	instrInfo.IsConditional = false
	instrInfo.BranchAddr = 0
	instrInfo.SubType = SubTypeNone

	switch currentISA {
	case common.IsaA64:
		return decodeA64(instrInfo, info)
	case common.IsaArm32:
		return decodeA32(instrInfo, info)
	case common.IsaThumb:
		return decodeT32(instrInfo, info)
	}
	return nil
}

// --- AArch64 ---

func decodeA64(instrInfo *common.InstrInfo, info *DecodeInfo) error {
	inst := instrInfo.Opcode
	instrInfo.InstrSize = 4

	if InstA64IsIndirectBranchLink(inst, &instrInfo.IsLink, info) {
		instrInfo.Type = common.InstrTypeIndirect
	} else if InstA64IsDirectBranchLink(inst, &instrInfo.IsLink, info) {
		instrInfo.Type = common.InstrTypeBranch
		dest, ok := InstA64BranchDestination(instrInfo.InstrAddr, inst)
		if ok {
			instrInfo.BranchAddr = dest
		}
	}

	instrInfo.IsConditional = InstA64IsConditional(inst)
	instrInfo.SubType = info.InstrSubType
	return nil
}

func InstA64IsIndirectBranchLink(inst uint32, isLink *bool, info *DecodeInfo) bool {
	if (inst & 0xffdffc1f) == 0xd61f0000 { // BR, BLR
		if (inst & 0x00200000) != 0 {
			*isLink = true
			info.InstrSubType = SubTypeBrLink
		}
		return true
	} else if (inst & 0xfffffc1f) == 0xd65f0000 { // RET
		info.InstrSubType = SubTypeV8Ret
		return true
	} else if (inst & 0xffffffff) == 0xd69f03e0 { // ERET
		info.InstrSubType = SubTypeV8Eret
		return true
	}
	return false
}

func InstA64IsDirectBranchLink(inst uint32, isLink *bool, info *DecodeInfo) bool {
	if (inst & 0x7c000000) == 0x34000000 { // CB, TB
		return true
	} else if (inst & 0xff000000) == 0x54000000 { // B.cond
		return true
	} else if (inst & 0x7c000000) == 0x14000000 { // B, BL imm
		if (inst & 0x80000000) != 0 {
			*isLink = true
			info.InstrSubType = SubTypeBrLink
		}
		return true
	}
	return false
}

func InstA64BranchDestination(addr uint64, inst uint32) (uint64, bool) {
	if (inst & 0xff000000) == 0x54000000 { // B.cond
		offset := SignExtend32((inst&0x00ffffe0)>>5, 19) << 2
		return addr + uint64(offset), true
	} else if (inst & 0x7c000000) == 0x14000000 { // B, BL imm
		offset := SignExtend32(inst&0x03ffffff, 26) << 2
		return addr + uint64(offset), true
	} else if (inst & 0x7e000000) == 0x34000000 { // CB
		offset := SignExtend32((inst&0x00ffffe0)>>5, 19) << 2
		return addr + uint64(offset), true
	} else if (inst & 0x7e000000) == 0x36000000 { // TB
		offset := SignExtend32((inst&0x0007ffe0)>>5, 14) << 2
		return addr + uint64(offset), true
	}
	return 0, false
}

func InstA64IsConditional(inst uint32) bool {
	return (inst&0x7c000000) == 0x34000000 || (inst&0xff000000) == 0x54000000
}

// --- ARM (A32) ---

func decodeA32(instrInfo *common.InstrInfo, info *DecodeInfo) error {
	inst := instrInfo.Opcode
	instrInfo.InstrSize = 4

	if InstArmIsIndirectBranch(inst, info) {
		instrInfo.Type = common.InstrTypeIndirect
		instrInfo.IsLink = InstArmIsBranchAndLink(inst)
	} else if InstArmIsDirectBranch(inst) {
		instrInfo.Type = common.InstrTypeBranch
		dest, ok := InstArmBranchDestination(uint32(instrInfo.InstrAddr), inst)
		if ok {
			instrInfo.BranchAddr = uint64(dest)
			// H bit (Thumb switch) logic handled in destination calc
			if (dest & 1) != 0 {
				instrInfo.NextISA = common.IsaThumb
				instrInfo.BranchAddr = uint64(dest &^ 1)
			}
		}
		instrInfo.IsLink = InstArmIsBranchAndLink(inst)
	}

	instrInfo.IsConditional = InstArmIsConditional(inst)
	instrInfo.SubType = info.InstrSubType
	return nil
}

func InstArmIsIndirectBranch(inst uint32, info *DecodeInfo) bool {
	if (inst & 0xf0000000) == 0xf0000000 {
		return (inst & 0xfe500000) == 0xf8100000 // RFE
	} else if (inst & 0x0ff000d0) == 0x01200010 { // BX, BLX (reg)
		if (inst & 0xFF) == 0x1E {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0x0e108000) == 0x08108000 { // POP {pc}
		if (inst & 0x0FFFA000) == 0x08BD8000 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0x0e50f000) == 0x0410f000 { // LDR PC, imm
		if (inst & 0x01ff0000) == 0x009D0000 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0x0e50f010) == 0x0610f000 { // LDR PC, reg
		return true
	} else if (inst & 0x0fe0f000) == 0x01a0f000 { // MOV PC, rx
		if (inst & 0x00100FFF) == 0x00E {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0x0e00f000) == 0x0000f000 { // DP PC, reg
		if (inst&0x0f900080) == 0x01000000 || (inst&0x0f9000f0) == 0x01800090 ||
			(inst&0x0fb0f000) == 0x0320f000 || (inst&0x0f90f000) == 0x0310f000 {
			return false
		}
		return true
	}
	return false
}

func InstArmIsDirectBranch(inst uint32) bool {
	if (inst & 0xf0000000) == 0xf0000000 {
		if (inst & 0xfe000000) == 0xfa000000 {
			return true // BLX (imm)
		}
		return false
	} else if (inst & 0x0e000000) == 0x0a000000 {
		return true // B, BL
	}
	return false
}

func InstArmBranchDestination(addr uint32, inst uint32) (uint32, bool) {
	if (inst & 0x0e000000) == 0x0a000000 {
		offset := SignExtend32(inst&0xffffff, 24) << 2
		npc := addr + 8 + uint32(offset)
		if (inst & 0xf0000000) == 0xf0000000 {
			npc |= 1 // Switch to Thumb
			npc |= ((inst >> 23) & 2)
		}
		return npc, true
	}
	return 0, false
}

func InstArmIsBranchAndLink(inst uint32) bool {
	if (inst & 0xf0000000) == 0xf0000000 {
		if (inst & 0xfe000000) == 0xfa000000 {
			return true // BLX (imm)
		}
	} else if (inst & 0x0f000000) == 0x0b000000 {
		return true // BL
	} else if (inst & 0x0ff000f0) == 0x01200030 {
		return true // BLX (reg)
	}
	return false
}

func InstArmIsConditional(inst uint32) bool {
	return (inst & 0xe0000000) != 0xe0000000
}

// --- Thumb (T32) ---

func decodeT32(instrInfo *common.InstrInfo, info *DecodeInfo) error {
	// Swap halfwords: Input 0xHW2HW1 -> 0xHW1HW2
	inst := instrInfo.Opcode
	op32 := (inst >> 16) | (inst << 16)

	// Determine size by checking HW1 (which is now in the upper 16 bits)
	is32 := (op32 & 0xF8000000) >= 0xE8000000

	if is32 {
		instrInfo.InstrSize = 4
	} else {
		instrInfo.InstrSize = 2
		// For 16-bit instructions, clear the lower 16 bits so decoders don't see garbage
		op32 &= 0xFFFF0000
	}

	if InstThumbIsDirectBranchLink(op32, &instrInfo.IsLink, &instrInfo.IsConditional, info) {
		instrInfo.Type = common.InstrTypeBranch
		dest, ok := InstThumbBranchDestination(uint32(instrInfo.InstrAddr), op32)
		if ok {
			instrInfo.BranchAddr = uint64(dest &^ 1)
			if (dest & 1) == 0 {
				instrInfo.NextISA = common.IsaArm32
			}
		}
	} else if InstThumbIsIndirectBranchLink(op32, &instrInfo.IsLink, info) {
		instrInfo.Type = common.InstrTypeIndirect
	}

	if !instrInfo.IsConditional {
		instrInfo.IsConditional = InstThumbIsConditional(op32)
	}
	instrInfo.SubType = info.InstrSubType
	return nil
}

func InstThumbIsDirectBranchLink(inst uint32, isLink *bool, isCond *bool, info *DecodeInfo) bool {
	if (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000 {
		*isCond = true
		return true // B<c> T1
	} else if (inst & 0xf8000000) == 0xe0000000 {
		return true // B T2
	} else if (inst&0xf800d000) == 0xf0008000 && (inst&0x03800000) != 0x03800000 {
		*isCond = true
		return true // B T3
	} else if (inst & 0xf8009000) == 0xf0009000 {
		if (inst & 0x00004000) != 0 {
			*isLink = true
			info.InstrSubType = SubTypeBrLink
		}
		return true // B T4, BL T1
	} else if (inst & 0xf800d001) == 0xf000c000 {
		*isLink = true
		info.InstrSubType = SubTypeBrLink
		return true // BLX (imm)
	} else if (inst & 0xf5000000) == 0xb1000000 {
		*isCond = true
		return true // CB(N)Z
	}
	return false
}

func InstThumbIsIndirectBranchLink(inst uint32, isLink *bool, info *DecodeInfo) bool {
	if (inst & 0xff000000) == 0x47000000 { // BX, BLX
		if (inst & 0x00800000) != 0 {
			*isLink = true
			info.InstrSubType = SubTypeBrLink
		} else if (inst & 0x00780000) == 0x00700000 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0xff000000) == 0xbd000000 { // POP {pc}
		info.InstrSubType = SubTypeV7ImpliedRet
		return true
	} else if (inst & 0xfd870000) == 0x44870000 { // MOV/ADD PC
		if (inst & 0xffff0000) == 0x46f70000 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst&0xfff0f800) == 0xf850f800 || (inst&0xfff0f000) == 0xf8d0f000 || (inst&0xff7ff000) == 0xf85ff000 {
		// LDR PC
		if (inst&0xfff0f800) == 0xf850f800 && (inst&0x000f0f00) == 0x000d0b00 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0xfe508000) == 0xe8108000 { // LDM PC
		if (inst & 0x0FFF0000) == 0x08BD0000 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	}
	return false
}

func InstThumbBranchDestination(addr uint32, inst uint32) (uint32, bool) {
	var npc uint32
	valid := true
	isaBit := uint32(1) // Default to Thumb

	if (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000 {
		offset := SignExtend32((inst&0x00ff0000)>>16, 8) << 1
		npc = addr + 4 + uint32(offset)
	} else if (inst & 0xf8000000) == 0xe0000000 {
		offset := SignExtend32((inst&0x07ff0000)>>16, 11) << 1
		npc = addr + 4 + uint32(offset)
	} else if (inst&0xf800d000) == 0xf0008000 && (inst&0x03800000) != 0x03800000 {
		// B T3
		s := (inst & 0x04000000) >> 26
		j1 := (inst & 0x2000) >> 13
		j2 := (inst & 0x0800) >> 11
		imm6 := (inst & 0x003f0000) >> 16
		imm11 := inst & 0x000007ff
		offset := (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1)
		npc = addr + 4 + uint32(SignExtend32(offset, 21))
	} else if (inst & 0xf8009000) == 0xf0009000 {
		// B T4 / BL T1
		s := (inst & 0x04000000) >> 26
		j1 := (inst & 0x2000) >> 13
		j2 := (inst & 0x0800) >> 11
		imm10 := (inst & 0x03ff0000) >> 16
		imm11 := inst & 0x000007ff
		i1 := ^(j1 ^ s) & 1
		i2 := ^(j2 ^ s) & 1
		offset := (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
		npc = addr + 4 + uint32(SignExtend32(offset, 25))
	} else if (inst & 0xf800d001) == 0xf000c000 {
		// BLX (imm) T2
		s := (inst & 0x04000000) >> 26
		j1 := (inst & 0x2000) >> 13
		j2 := (inst & 0x0800) >> 11
		imm10 := (inst & 0x03ff0000) >> 16
		imm11h := (inst & 0x000007fe) // bit 0 is 0
		i1 := ^(j1 ^ s) & 1
		i2 := ^(j2 ^ s) & 1
		offset := (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | imm11h
		npc = (addr + 4) & ^uint32(3) // Align PC to 4
		npc += uint32(SignExtend32(offset, 25))
		isaBit = 0 // Switch to ARM
	} else if (inst & 0xf5000000) == 0xb1000000 {
		i := (inst & 0x02000000) >> 25
		imm5 := (inst & 0x00f80000) >> 19
		offset := (i << 6) | (imm5 << 1)
		npc = addr + 4 + offset
	} else {
		valid = false
	}
	if valid {
		return npc | isaBit, true
	}
	return 0, false
}

func InstThumbIsConditional(inst uint32) bool {
	if (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000 {
		return true
	}
	if (inst & 0xf5000000) == 0xb1000000 {
		return true
	}
	if (inst&0xf800d000) == 0xf0008000 && (inst&0x03800000) != 0x03800000 {
		return true
	}
	return false
}
