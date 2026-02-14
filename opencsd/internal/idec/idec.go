package idec

// DecodeInfo holds supplementary info for decoding.
type DecodeInfo struct {
	ArchVersion  string // Simplified for now
	InstrSubType int
}

const (
	SubTypeNone         = 0
	SubTypeBrLink       = 1
	SubTypeV7ImpliedRet = 2
	SubTypeV8Ret        = 3
	SubTypeV8Eret       = 4
)

// SignExtend32 simulates C++ signed shift behavior for sign extension.
func SignExtend32(val uint32, bits int) int32 {
	shift := 32 - bits
	return int32(val<<uint(shift)) >> uint(shift)
}

// --- ARM (A32) Logic ---

func InstArmIsBranch(inst uint32, info *DecodeInfo) bool {
	return InstArmIsIndirectBranch(inst, info) || InstArmIsDirectBranch(inst)
}

func InstArmIsDirectBranch(inst uint32) bool {
	if (inst & 0xf0000000) == 0xf0000000 {
		// NV space
		if (inst & 0xfe000000) == 0xfa000000 {
			return true // BLX (imm)
		}
		return false
	} else if (inst & 0x0e000000) == 0x0a000000 {
		return true // B, BL
	}
	return false
}

func InstArmIsIndirectBranch(inst uint32, info *DecodeInfo) bool {
	if (inst & 0xf0000000) == 0xf0000000 {
		return (inst & 0xfe500000) == 0xf8100000 // RFE
	} else if (inst & 0x0ff000d0) == 0x01200010 { // BX, BLX (reg)
		if (inst & 0xFF) == 0x1E {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0x0e108000) == 0x08108000 { // POP {pc} or LDM
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
		// Exclude MSR, TST, CMP etc
		if (inst&0x0f900080) == 0x01000000 || (inst&0x0f9000f0) == 0x01800090 ||
			(inst&0x0fb0f000) == 0x0320f000 || (inst&0x0f90f000) == 0x0310f000 {
			return false
		}
		return true
	}
	return false
}

func InstArmBranchDestination(addr uint32, inst uint32) (uint32, bool) {
	if (inst & 0x0e000000) == 0x0a000000 {
		// B, BL, BLX
		// Sign extend 24 bits, shift left 2
		offset := SignExtend32(inst&0xffffff, 24) << 2
		npc := addr + 8 + uint32(offset)

		if (inst & 0xf0000000) == 0xf0000000 {
			npc |= 1                  // Switch to Thumb
			npc |= ((inst >> 23) & 2) // Apply H bit
		}
		return npc, true
	}
	return 0, false
}

func InstArmIsConditional(inst uint32) bool {
	return (inst & 0xe0000000) != 0xe0000000
}

// --- Thumb (T32) Logic ---

func InstThumbIsBranch(inst uint32, info *DecodeInfo) bool {
	// Note: 16-bit instructions passed as high halfword (xxxx0000)
	return InstThumbIsIndirectBranch(inst, info) || InstThumbIsDirectBranch(inst, info)
}

func InstThumbIsDirectBranch(inst uint32, info *DecodeInfo) bool {
	if (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000 {
		return true // B<c> T1
	} else if (inst & 0xf8000000) == 0xe0000000 {
		return true // B T2
	} else if (inst&0xf800d000) == 0xf0008000 && (inst&0x03800000) != 0x03800000 {
		return true // B T3
	} else if (inst & 0xf8009000) == 0xf0009000 {
		if (inst & 0x00004000) != 0 {
			info.InstrSubType = SubTypeBrLink
		}
		return true // B T4, BL T1
	} else if (inst & 0xf800d001) == 0xf000c000 {
		info.InstrSubType = SubTypeBrLink
		return true // BLX (imm)
	} else if (inst & 0xf5000000) == 0xb1000000 {
		return true // CB(N)Z
	}
	return false
}

func InstThumbIsIndirectBranch(inst uint32, info *DecodeInfo) bool {
	if (inst & 0xff000000) == 0x47000000 { // BX, BLX (reg)
		if (inst & 0x00800000) != 0 {
			info.InstrSubType = SubTypeBrLink
		} else if (inst & 0x00780000) == 0x00700000 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst & 0xff000000) == 0xbd000000 { // POP {pc}
		info.InstrSubType = SubTypeV7ImpliedRet
		return true
	} else if (inst & 0xfd870000) == 0x44870000 { // MOV/ADD PC, reg
		if (inst & 0xffff0000) == 0x46f70000 {
			info.InstrSubType = SubTypeV7ImpliedRet
		}
		return true
	} else if (inst&0xfff0f800) == 0xf850f800 || (inst&0xfff0f000) == 0xf8d0f000 || (inst&0xff7ff000) == 0xf85ff000 {
		// LDR PC (T3, T4, T2)
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
	// Simplified: ignoring TBB/TBH, RFE, ERET for brevity in this snippet
	return false
}

func InstThumbBranchDestination(addr uint32, inst uint32) (uint32, bool) {
	var npc uint32
	valid := true

	if (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000 {
		// B<c> T1
		offset := SignExtend32((inst&0x00ff0000)>>16, 8) << 1
		npc = addr + 4 + uint32(offset)
	} else if (inst & 0xf8000000) == 0xe0000000 {
		// B T2
		offset := SignExtend32((inst&0x07ff0000)>>16, 11) << 1
		npc = addr + 4 + uint32(offset)
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
	} else if (inst & 0xf5000000) == 0xb1000000 {
		// CB(N)Z
		i := (inst & 0x02000000) >> 25
		imm5 := (inst & 0x00f80000) >> 19
		offset := (i << 6) | (imm5 << 1)
		npc = addr + 4 + offset
	} else {
		valid = false
	}

	if valid {
		return npc | 1, true // Thumb bit set
	}
	return 0, false
}

func InstThumbIsConditional(inst uint32) bool {
	if (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000 {
		return true // B<c> T1
	}
	if (inst & 0xf5000000) == 0xb1000000 {
		return true // CB(N)Z
	}
	// T3 B<c> omitted for brevity
	return false
}

// --- AArch64 Logic ---

func InstA64IsBranch(inst uint32, info *DecodeInfo) bool {
	return InstA64IsIndirectBranch(inst, info) || InstA64IsDirectBranch(inst, info)
}

func InstA64IsDirectBranch(inst uint32, info *DecodeInfo) bool {
	if (inst & 0x7c000000) == 0x34000000 {
		return true // CB, TB
	} else if (inst & 0xff000000) == 0x54000000 {
		return true // B.cond
	} else if (inst & 0x7c000000) == 0x14000000 {
		// B, BL imm
		if (inst & 0x80000000) != 0 {
			info.InstrSubType = SubTypeBrLink
		}
		return true
	}
	return false
}

func InstA64IsIndirectBranch(inst uint32, info *DecodeInfo) bool {
	if (inst & 0xffdffc1f) == 0xd61f0000 { // BR, BLR
		if (inst & 0x00200000) != 0 {
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
	// CB, TB, B.cond
	return (inst&0x7c000000) == 0x34000000 || (inst&0xff000000) == 0x54000000
}
