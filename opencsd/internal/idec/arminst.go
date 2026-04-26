package idec

import "opencsd/internal/ocsd"

// DecodeInfo provides supplementary decode information
type DecodeInfo struct {
	ArchVersion  ocsd.ArchVersion
	InstrSubType ocsd.InstrSubtype
}

// IsWideThumb tests if a halfword is the first half of a 32-bit instruction,
// as opposed to a complete 16-bit instruction.
func IsWideThumb(insthw uint16) bool {
	return (insthw & 0xF800) >= 0xE800
}

// InstARMIsDirectBranch tests whether an instruction is a direct (aka immediate) branch.
// Performance event 0x0D counts these.
func InstARMIsDirectBranch(inst uint32) bool {
	switch {
	case (inst & 0xf0000000) == 0xf0000000:
		// NV space
		return (inst & 0xfe000000) == 0xfa000000 // BLX (imm)
	case (inst & 0x0e000000) == 0x0a000000:
		// B, BL
		return true
	default:
		return false
	}
}

func InstARMWfiWfe(inst uint32) bool {
	// WFI & WFE may be traced as branches in etm4.3 ++
	return inst&0xf0000000 != 0xf0000000 && inst&0x0ffffffe == 0x0320f002
}

func InstARMIsIndirectBranch(inst uint32, info *DecodeInfo) bool {
	switch {
	case (inst & 0xf0000000) == 0xf0000000:
		// NV space
		return (inst & 0xfe500000) == 0xf8100000 // RFE
	case (inst & 0x0ff000d0) == 0x01200010:
		// BLX (register), BX
		if (inst & 0xFF) == 0x1E {
			info.InstrSubType = ocsd.SInstrV7ImpliedRet // BX LR
		}
		return true
	case (inst & 0x0ff000f0) == 0x01200020:
		// BXJ: in v8 this behaves like BX
		return true
	case (inst & 0x0e108000) == 0x08108000:
		// POP {...,pc} or LDMxx {...,pc}
		if (inst & 0x0FFFA000) == 0x08BD8000 { // LDMIA SP!,{...,pc}
			info.InstrSubType = ocsd.SInstrV7ImpliedRet
		}
		return true
	case (inst & 0x0e50f000) == 0x0410f000:
		// LDR PC,imm... inc. POP {PC}
		if (inst & 0x01ff0000) == 0x009D0000 {
			info.InstrSubType = ocsd.SInstrV7ImpliedRet // LDR PC, [SP], #imm
		}
		return true
	case (inst & 0x0e50f010) == 0x0610f000:
		// LDR PC,reg
		return true
	case (inst & 0x0fe0f000) == 0x01a0f000:
		// MOV PC,rx
		if (inst & 0x00100FFF) == 0x00E { // ensure the S=0, LSL #0 variant - i.e plain MOV
			info.InstrSubType = ocsd.SInstrV7ImpliedRet // MOV PC, R14
		}
		return true
	case (inst & 0x0f900080) == 0x01000000:
		// "Miscellaneous instructions" - in DP space
		return false
	case (inst & 0x0f9000f0) == 0x01800090:
		// Some extended loads and stores
		return false
	case (inst & 0x0fb0f000) == 0x0320f000:
		// MSR #imm
		return false
	case (inst & 0x0e00f000) == 0x0200f000:
		// DP PC,imm shift
		return (inst & 0x0f90f000) != 0x0310f000 // TST/CMP return false
	case (inst & 0x0e00f000) == 0x0000f000:
		// DP PC,reg
		return true
	default:
		return false
	}
}

func InstThumbIsDirectBranch(inst uint32, info *DecodeInfo) bool {
	isBranch, _, _ := InstThumbIsDirectBranchLink(inst, info)
	return isBranch
}

func InstThumbIsDirectBranchLink(inst uint32, info *DecodeInfo) (isBranch, isLink, isCond bool) {
	switch {
	case (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000:
		// B<c> (encoding T1)
		return true, false, true
	case (inst & 0xf8000000) == 0xe0000000:
		// B (encoding T2)
		return true, false, false
	case (inst&0xf800d000) == 0xf0008000 && (inst&0x03800000) != 0x03800000:
		// B (encoding T3)
		return true, false, true
	case (inst & 0xf8009000) == 0xf0009000:
		// B (encoding T4); BL (encoding T1)
		if (inst & 0x00004000) != 0 {
			info.InstrSubType = ocsd.SInstrBrLink
			return true, true, false
		}
		return true, false, false
	case (inst & 0xf800d001) == 0xf000c000:
		// BLX (imm) (encoding T2)
		info.InstrSubType = ocsd.SInstrBrLink
		return true, true, false
	case (inst & 0xf5000000) == 0xb1000000:
		// CB(NZ)
		return true, false, true
	case (inst & 0xfffff001) == 0xf00fc001, // LE (encoding T1)
		(inst & 0xfffff001) == 0xf02fc001, // LE (encoding T2)
		(inst & 0xfffff001) == 0xf01fc001, // LETP (encoding T3)
		(inst & 0xfff0f001) == 0xf040c001, // WLS (encoding T1)
		(inst & 0xffc0f001) == 0xf000c001: // WLSTP (encoding T3)
		return true, false, false
	default:
		return false, false, false
	}
}

func InstThumbWfiWfe(inst uint32) bool {
	// WFI, WFE may be branches in etm4.3++.
	return inst&0xfffffffe == 0xf3af8002 || // encoding T2
		inst&0xffef0000 == 0xbf200000 // encoding T1
}

func InstThumbIsIndirectBranch(inst uint32, info *DecodeInfo) bool {
	isBranch, _ := InstThumbIsIndirectBranchLink(inst, info)
	return isBranch
}

func InstThumbIsIndirectBranchLink(inst uint32, info *DecodeInfo) (isBranch, isLink bool) {
	// See e.g. PFT Table 2-3 and Table 2-5
	switch {
	case (inst & 0xff000000) == 0x47000000:
		// BX, BLX (reg) [v8M includes BXNS, BLXNS]
		if (inst & 0x00800000) != 0 {
			info.InstrSubType = ocsd.SInstrBrLink
			return true, true
		} else if (inst & 0x00780000) == 0x00700000 {
			info.InstrSubType = ocsd.SInstrV7ImpliedRet // BX LR
		}
		return true, false
	case (inst & 0xfff0d000) == 0xf3c08000:
		// BXJ: in v8 this behaves like BX
		return true, false
	case (inst & 0xff000000) == 0xbd000000:
		// POP {pc}
		info.InstrSubType = ocsd.SInstrV7ImpliedRet
		return true, false
	case (inst & 0xfd870000) == 0x44870000:
		// MOV PC,reg or ADD PC,reg
		if (inst & 0xffff0000) == 0x46f70000 {
			info.InstrSubType = ocsd.SInstrV7ImpliedRet // MOV PC,LR
		}
		return true, false
	case (inst & 0xfff0ffe0) == 0xe8d0f000:
		// TBB/TBH
		return true, false
	case (inst & 0xffd00000) == 0xe8100000:
		// RFE (T1)
		return true, false
	case (inst & 0xffd00000) == 0xe9900000:
		// RFE (T2)
		return true, false
	case (inst & 0xfff0d000) == 0xf3d08000:
		// SUBS PC,LR,#imm inc.ERET
		return true, false
	case (inst & 0xfff0f000) == 0xf8d0f000:
		// LDR PC,imm (T3)
		return true, false
	case (inst & 0xff7ff000) == 0xf85ff000:
		// LDR PC,literal (T2)
		return true, false
	case (inst & 0xfff0f800) == 0xf850f800:
		// LDR PC,imm (T4)
		if (inst & 0x000f0f00) == 0x000d0b00 {
			info.InstrSubType = ocsd.SInstrV7ImpliedRet // LDR PC, [SP], #imm
		}
		return true, false
	case (inst & 0xfff0ffc0) == 0xf850f000:
		// LDR PC,reg (T2)
		return true, false
	case (inst & 0xfe508000) == 0xe8108000:
		// LDM PC
		if (inst & 0x0FFF0000) == 0x08BD0000 { // LDMIA [SP]!,
			info.InstrSubType = ocsd.SInstrV7ImpliedRet // POP {...,pc}
		}
		return true, false
	default:
		return false, false
	}
}

func InstA64IsDirectBranch(inst uint32, info *DecodeInfo) bool {
	isBranch, _ := InstA64IsDirectBranchLink(inst, info)
	return isBranch
}

func InstA64IsCmpBr(inst uint32) bool {
	opcode := inst & 0xFF000000
	desc := inst & 0x0000C000

	switch opcode {
	case 0x74000000:
		// CBB, CB reg (SF=0), CBH: desc 0b00, 0b10, 0b11.
		return desc != 0x4000
	case 0xF4000000:
		// CB <cc> reg SF=1: desc 0b00.
		return desc == 0
	case 0x75000000, 0xF5000000:
		// CB <cc> imm: SF=x.
		return desc&0x4000 == 0
	default:
		return false
	}
}

func InstA64CmpBrDestination(inst uint32, addr64 uint64) uint64 {
	// label imm9 - 13:5
	return addr64 + uint64(int64(int32((inst&0x00003fe0)<<18)>>21))
}

func InstA64IsDirectBranchLink(inst uint32, info *DecodeInfo) (isBranch, isLink bool) {
	switch {
	case (inst & 0x7c000000) == 0x34000000,
		(inst & 0xff000000) == 0x54000000:
		// CB, TB, B<cond>
		return true, false
	case (inst & 0x7c000000) == 0x14000000:
		// B, BL imm
		if (inst & 0x80000000) != 0 {
			info.InstrSubType = ocsd.SInstrBrLink
			return true, true
		}
		return true, false
	case InstA64IsCmpBr(inst):
		// CB <cc>, CBB <cc>, CBH <cc>
		return true, false
	default:
		return false, false
	}
}

func InstA64WfiWfe(inst uint32, info *DecodeInfo) bool {
	// WFI, WFE may be traced as branches in etm 4.3++.
	if inst&0xffffffdf == 0xd503205f {
		return true
	}
	// WFIT / WFET for later archs.
	return ocsd.IsArchMinVer(info.ArchVersion, ocsd.ArchAA64) && inst&0xffffffc0 == 0xd5031000
}

func InstA64Tstart(inst uint32) bool {
	return (inst & 0xffffffe0) == 0xd5233060
}

func InstA64IsIndirectBranch(inst uint32, info *DecodeInfo) bool {
	isBranch, _ := InstA64IsIndirectBranchLink(inst, info)
	return isBranch
}

func InstA64IsIndirectBranchLink(inst uint32, info *DecodeInfo) (isBranch, isLink bool) {
	switch {
	case (inst & 0xffdffc1f) == 0xd61f0000:
		// BR, BLR
		if (inst & 0x00200000) != 0 {
			info.InstrSubType = ocsd.SInstrBrLink
			return true, true
		}
		return true, false
	case (inst & 0xfffffc1f) == 0xd65f0000:
		// RET
		info.InstrSubType = ocsd.SInstrV8Ret
		return true, false
	case (inst & 0xffffffff) == 0xd69f03e0:
		// ERET
		info.InstrSubType = ocsd.SInstrV8Eret
		return true, false
	case ocsd.IsArchMinVer(info.ArchVersion, ocsd.ArchV8r3):
		// new pointer auth instr for v8.3 arch
		switch {
		case (inst & 0xffdff800) == 0xd71f0800:
			// BRAA, BRAB, BLRAA, BLRBB
			if (inst & 0x00200000) != 0 {
				info.InstrSubType = ocsd.SInstrBrLink
				return true, true
			}
			return true, false
		case (inst & 0xffdff81F) == 0xd61f081F:
			// BRAAZ, BRABZ, BLRAAZ, BLRBBZ
			if (inst & 0x00200000) != 0 {
				info.InstrSubType = ocsd.SInstrBrLink
				return true, true
			}
			return true, false
		case (inst & 0xfffffbff) == 0xd69f0bff:
			// ERETAA, ERETAB
			info.InstrSubType = ocsd.SInstrV8Eret
			return true, false
		case (inst & 0xfffffbff) == 0xd65f0bff:
			// RETAA, RETAB
			info.InstrSubType = ocsd.SInstrV8Ret
			return true, false
		case (inst & 0xffc0001f) == 0x5500001f:
			// RETA<k>SPPC label
			info.InstrSubType = ocsd.SInstrV8Ret
			return true, false
		case ((inst & 0xfffffbe0) == 0xd65f0be0) && ((inst & 0x1f) != 0x1f):
			// RETA<k>SPPC <register>
			info.InstrSubType = ocsd.SInstrV8Ret
			return true, false
		case (inst == 0xd6ff03e0) || (inst == 0xd6ff07e0):
			// TEXIT - acts as ERET
			info.InstrSubType = ocsd.SInstrV8Eret
			return true, false
		default:
			return false, false
		}
	default:
		return false, false
	}
}

func InstARMBranchDestination(addr uint32, inst uint32) (pnpc uint32, ok bool) {
	if (inst & 0x0e000000) == 0x0a000000 {
		pnpc = addr + 8 + uint32(int32((inst&0xffffff)<<8)>>6)
		if (inst & 0xf0000000) == 0xf0000000 {
			pnpc |= 1                  // indicate ISA is now Thumb
			pnpc |= ((inst >> 23) & 2) // apply the H bit
		}
		return pnpc, true
	}
	return 0, false
}

func InstThumbBranchDestination(addr uint32, inst uint32) (pnpc uint32, ok bool) {
	switch {
	case (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000:
		// B<c> (encoding T1)
		pnpc = addr + 4 + uint32(int32((inst&0x00ff0000)<<8)>>23)
		pnpc |= 1
		return pnpc, true
	case (inst & 0xf8000000) == 0xe0000000:
		// B (encoding T2)
		pnpc = addr + 4 + uint32(int32((inst&0x07ff0000)<<5)>>20)
		pnpc |= 1
		return pnpc, true
	case (inst&0xf800d000) == 0xf0008000 && (inst&0x03800000) != 0x03800000:
		// B (encoding T3)
		offset := ((inst & 0x04000000) << 5) |
			((inst & 0x0800) << 19) |
			((inst & 0x2000) << 16) |
			((inst & 0x003f0000) << 7) |
			((inst & 0x000007ff) << 12)
		pnpc = addr + 4 + uint32(int32(offset)>>11)
		pnpc |= 1
		return pnpc, true
	case (inst & 0xf8009000) == 0xf0009000:
		// B (encoding T4); BL (encoding T1)
		S := ((inst & 0x04000000) >> 26) - 1 // ffffffff or 0 according to S bit
		offset := ((inst & 0x04000000) << 5) |
			(((inst ^ S) & 0x2000) << 17) |
			(((inst ^ S) & 0x0800) << 18) |
			((inst & 0x03ff0000) << 3) |
			((inst & 0x000007ff) << 8)
		pnpc = addr + 4 + uint32(int32(offset)>>7)
		pnpc |= 1
		return pnpc, true
	case (inst & 0xf800d001) == 0xf000c000:
		// BLX (encoding T2)
		S := ((inst & 0x04000000) >> 26) - 1 // ffffffff or 0 according to S bit
		addr &= 0xfffffffc                   // Align(PC,4)
		offset := ((inst & 0x04000000) << 5) |
			(((inst ^ S) & 0x2000) << 17) |
			(((inst ^ S) & 0x0800) << 18) |
			((inst & 0x03ff0000) << 3) |
			((inst & 0x000007fe) << 8)
		pnpc = addr + 4 + uint32(int32(offset)>>7)
		// don't set the Thumb bit, as we're transferring to ARM
		return pnpc, true
	case (inst & 0xf5000000) == 0xb1000000:
		// CB(NZ)
		// Note that it's zero-extended - always a forward branch
		pnpc = addr + 4 + ((((inst & 0x02000000) << 6) | ((inst & 0x00f80000) << 7)) >> 25)
		pnpc |= 1
		return pnpc, true
	case (inst & 0xfffff001) == 0xf00fc001, // LE (encoding T1)
		(inst & 0xfffff001) == 0xf02fc001, // LE (encoding T2)
		(inst & 0xfffff001) == 0xf01fc001: // LETP (encoding T3)
		pnpc = addr + 4 - (((inst & 0x000007fe) << 1) | ((inst & 0x00000800) >> 10))
		pnpc |= 1
		return pnpc, true
	case (inst & 0xfff0f001) == 0xf040c001, // WLS (encoding T1)
		(inst & 0xffc0f001) == 0xf000c001: // WLSTP (encoding T3)
		pnpc = addr + 4 + (((inst & 0x000007fe) << 1) | ((inst & 0x00000800) >> 10))
		pnpc |= 1
		return pnpc, true
	default:
		return 0, false
	}
}

func InstA64BranchDestination(addr uint64, inst uint32, pnpc *uint64) bool {
	var npc uint64
	switch {
	case (inst & 0xff000000) == 0x54000000:
		// B<cond>, BC<cond>
		npc = addr + uint64(int64(int32((inst&0x00ffffe0)<<8)>>11))
	case (inst & 0x7c000000) == 0x14000000:
		// B, BL imm
		npc = addr + uint64(int64(int32((inst&0x03ffffff)<<6)>>4))
	case (inst & 0x7e000000) == 0x34000000:
		// CB
		npc = addr + uint64(int64(int32((inst&0x00ffffe0)<<8)>>11))
	case (inst & 0x7e000000) == 0x36000000:
		// TB
		npc = addr + uint64(int64(int32((inst&0x0007ffe0)<<13)>>16))
	case InstA64IsCmpBr(inst):
		npc = InstA64CmpBrDestination(inst, addr)
	default:
		return false
	}
	if pnpc != nil {
		*pnpc = npc
	}
	return true
}

func InstARMIsBranch(inst uint32, info *DecodeInfo) bool {
	return InstARMIsIndirectBranch(inst, info) || InstARMIsDirectBranch(inst)
}

func InstThumbIsBranch(inst uint32, info *DecodeInfo) bool {
	return InstThumbIsIndirectBranch(inst, info) || InstThumbIsDirectBranch(inst, info)
}

func InstA64IsBranch(inst uint32, info *DecodeInfo) bool {
	return InstA64IsIndirectBranch(inst, info) || InstA64IsDirectBranch(inst, info)
}

func InstARMIsBranchAndLink(inst uint32, info *DecodeInfo) bool {
	switch {
	case (inst&0xf0000000) == 0xf0000000 && (inst&0xfe000000) == 0xfa000000, // BLX (imm)
		(inst & 0x0f000000) == 0x0b000000, // BL
		(inst & 0x0ff000f0) == 0x01200030: // BLX (reg)
		info.InstrSubType = ocsd.SInstrBrLink
		return true
	default:
		return false
	}
}

func InstThumbIsBranchAndLink(inst uint32, info *DecodeInfo) bool {
	switch {
	case (inst & 0xff800000) == 0x47800000, // BLX (reg)
		(inst & 0xf800c000) == 0xf000c000: // BL, BLX (imm)
		info.InstrSubType = ocsd.SInstrBrLink
		return true
	default:
		return false
	}
}

func InstA64IsBranchAndLink(inst uint32, info *DecodeInfo) bool {
	switch {
	case (inst & 0xfffffc1f) == 0xd63f0000, // BLR
		(inst & 0xfc000000) == 0x94000000: // BL
		info.InstrSubType = ocsd.SInstrBrLink
		return true
	case ocsd.IsArchMinVer(info.ArchVersion, ocsd.ArchV8r3):
		// new pointer auth instr for v8.3 arch
		switch {
		case (inst & 0xfffff800) == 0xd73f0800, // BLRAA, BLRBB
			(inst & 0xfffff81F) == 0xd63f081F: // BLRAAZ, BLRBBZ
			info.InstrSubType = ocsd.SInstrBrLink
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func InstARMIsConditional(inst uint32) bool {
	return (inst & 0xe0000000) != 0xe0000000
}

func InstThumbIsConditional(inst uint32) bool {
	switch {
	case (inst&0xf0000000) == 0xd0000000 && (inst&0x0e000000) != 0x0e000000:
		// B<c> (encoding T1)
		return true
	case (inst&0xf800d000) == 0xf0008000 && (inst&0x03800000) != 0x03800000:
		// B<c> (encoding T3)
		return true
	case (inst & 0xf5000000) == 0xb1000000:
		// CB(N)Z
		return true
	default:
		return false
	}
}

func InstThumbIsIT(inst uint32) uint32 {
	if (inst&0xff000000) != 0xbf000000 || (inst&0x000f0000) == 0x00000000 {
		return 0
	}
	switch {
	case (inst & 0x00010000) != 0:
		return 4
	case (inst & 0x00020000) != 0:
		return 3
	case (inst & 0x00040000) != 0:
		return 2
	case (inst & 0x00080000) != 0:
		return 1
	default:
		return 0
	}
}

func InstA64IsConditional(inst uint32) bool {
	return inst&0x7c000000 == 0x34000000 || // CB, TB
		inst&0xff000000 == 0x54000000 // B.cond, BC.cond
}

type ArmBarrierT int

const (
	ArmBarrierNone ArmBarrierT = iota
	ArmBarrierIsb
	ArmBarrierDmb
	ArmBarrierDsb
)

func InstARMBarrier(inst uint32) ArmBarrierT {
	switch {
	case inst&0xfff00000 == 0xf5700000:
		return decodeSystemBarrier(inst & 0xf0)
	case inst&0x0fff0f00 == 0x0e070f00:
		return decodeCP15Barrier(inst & 0xff)
	default:
		return ArmBarrierNone
	}
}

func InstThumbBarrier(inst uint32) ArmBarrierT {
	switch {
	case inst&0xffffff00 == 0xf3bf8f00:
		return decodeSystemBarrier(inst & 0xf0)
	case inst&0xffff0f00 == 0xee070f00:
		// Thumb2 CP15 barriers are unlikely... 1156T2 only?
		return decodeCP15Barrier(inst & 0xff)
	default:
		return ArmBarrierNone
	}
}

func decodeSystemBarrier(value uint32) ArmBarrierT {
	switch value {
	case 0x40:
		return ArmBarrierDsb
	case 0x50:
		return ArmBarrierDmb
	case 0x60:
		return ArmBarrierIsb
	default:
		return ArmBarrierNone
	}
}

func decodeCP15Barrier(value uint32) ArmBarrierT {
	switch value {
	case 0x9a:
		return ArmBarrierDsb // mcr p15,0,Rt,c7,c10,4
	case 0xba:
		return ArmBarrierDmb // mcr p15,0,Rt,c7,c10,5
	case 0x95:
		return ArmBarrierIsb // mcr p15,0,Rt,c7,c5,4
	default:
		return ArmBarrierNone
	}
}

func InstA64Barrier(inst uint32) ArmBarrierT {
	if (inst & 0xfffff09f) != 0xd503309f {
		return ArmBarrierNone
	}
	switch inst & 0x60 {
	case 0x0:
		return ArmBarrierDsb
	case 0x20:
		return ArmBarrierDmb
	case 0x40:
		return ArmBarrierIsb
	default:
		return ArmBarrierNone
	}
}

func InstARMIsUDF(inst uint32) bool {
	return (inst & 0xfff000f0) == 0xe7f000f0
}

func InstThumbIsUDF(inst uint32) bool {
	switch {
	case (inst & 0xff000000) == 0xde000000:
		return true // T1
	case (inst & 0xfff0f000) == 0xf7f0a000:
		return true // T2
	default:
		return false
	}
}

func InstA64IsUDF(inst uint32) bool {
	// No A64 encodings are formally allocated as permanently undefined,
	// but OpenCSD treats the low and high 21-bit regions as undefined.
	return (inst&0xffe00000) == 0x00000000 ||
		(inst&0xffe00000) == 0xffe00000
}
