package idec

import (
	"opencsd/internal/ocsd"
	"testing"
)

type decodeCase struct {
	name     string
	opcode   uint32
	expected ocsd.InstrType
	subType  ocsd.InstrSubtype
	isLink   uint8
}

func checkDecode(t *testing.T, dec *Decoder, arch ocsd.ArchVersion, isa ocsd.ISA, tc decodeCase) {
	t.Helper()

	info := &ocsd.InstrInfo{
		PeType:          ocsd.ArchProfile{Arch: arch},
		ISA:             isa,
		InstrAddr:       0x1000,
		Opcode:          tc.opcode,
		DsbDmbWaypoints: 1,
		WfiWfeBranch:    1,
	}
	if err := dec.DecodeInstruction(info); err != nil {
		t.Fatalf("expected decode to succeed, got %v", err)
	}
	if info.Type != tc.expected {
		t.Errorf("expected type %v, got %v", tc.expected, info.Type)
	}
	if info.Subtype != tc.subType {
		t.Errorf("expected subtype %v, got %v", tc.subType, info.Subtype)
	}
	if info.IsLink != tc.isLink {
		t.Errorf("expected link flag %v, got %v", tc.isLink, info.IsLink)
	}
}

func TestDecoder_DecodeA32(t *testing.T) {
	dec := NewDecoder()

	tests := []decodeCase{
		{"Direct Branch (B)", 0xEA000000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch Link (BL)", 0xEB000000, ocsd.InstrBr, ocsd.SInstrBrLink, 1},
		{"Direct Branch Link (BLX imm)", 0xFA000000, ocsd.InstrBr, ocsd.SInstrBrLink, 1},

		{"Indirect Branch (BX LR)", 0x012FFF1E, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch Link (BLX reg)", 0x01200030, ocsd.InstrBrIndirect, ocsd.SInstrBrLink, 1},
		{"Indirect Branch RFE", 0xF8100000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch BXJ", 0x01200020, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDM", 0x08108000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDMIA SP!, {pc}", 0x08BD8000, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch LDR PC, imm", 0x0410f000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDR PC, [SP], #imm", 0x049Df000, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch LDR PC, reg", 0x0610f000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch MOV PC, rx", 0x01a0f000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch MOV PC, R14", 0x01a0f00E, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch DP PC, reg", 0x0000f000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch DP PC, imm", 0x0200f000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},

		{"ISB", 0xF57FF060, ocsd.InstrIsb, ocsd.SInstrNone, 0},
		{"DMB", 0xF57FF050, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},
		{"DSB", 0xF57FF040, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},

		{"CP15 ISB", 0x0E070F95, ocsd.InstrIsb, ocsd.SInstrNone, 0},
		{"CP15 DMB", 0x0E070FBA, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},
		{"CP15 DSB", 0x0E070F9A, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},

		{"WFI", 0xE320F003, ocsd.InstrWfiWfe, ocsd.SInstrNone, 0},

		{"Misc DP", 0x01000000, ocsd.InstrOther, ocsd.SInstrNone, 0},
		{"Misc Load", 0x01800090, ocsd.InstrOther, ocsd.SInstrNone, 0},
		{"MSR", 0x0320f000, ocsd.InstrOther, ocsd.SInstrNone, 0},
		{"TST/CMP PC", 0x0310f000, ocsd.InstrOther, ocsd.SInstrNone, 0},

		{"Other", 0xE0800000, ocsd.InstrOther, ocsd.SInstrNone, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkDecode(t, dec, ocsd.ArchV7, ocsd.ISAArm, tt)
		})
	}
}

func TestDecoder_DecodeT32(t *testing.T) {
	dec := NewDecoder()

	// Remember: Thumb32 opcodes must be swapped: e.g. 0xF0008000 in memory -> 0x8000F000
	// 16-bit opcodes are in lower half: 0x0000xxxx
	tests := []decodeCase{
		{"Direct Branch T1 (B<c>)", 0x0000D000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch T2 (B)", 0x0000E000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch T3 (B)", 0x8000F000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch T4 (B)", 0x9000F000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch Link (BL)", 0xD000F000, ocsd.InstrBr, ocsd.SInstrBrLink, 1}, // BL bit 14 set
		{"Direct Branch BLX imm", 0xC000F000, ocsd.InstrBr, ocsd.SInstrBrLink, 1},
		{"Direct Branch CBZ", 0x0000B100, ocsd.InstrBr, ocsd.SInstrNone, 0},

		{"Indirect Branch BX", 0x00004700, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch BX LR", 0x00004770, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch BLX reg", 0x00004780, ocsd.InstrBrIndirect, ocsd.SInstrBrLink, 1},
		{"Indirect Branch BXJ", 0x8000F3C0, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch POP {pc}", 0x0000BD00, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch MOV PC", 0x00004487, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch MOV PC, LR", 0x000046F7, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch TBB", 0xF000E8D0, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch RFE T1", 0x0000E810, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch RFE T2", 0x0000E990, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch SUBS PC, LR", 0x8000F3D0, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDR PC, imm T3", 0xF000F8D0, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDR PC, literal T2", 0xF000F85F, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDR PC, imm T4", 0xF800F850, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDR PC, [SP], #imm", 0xFB00F85D, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},
		{"Indirect Branch LDR PC, reg T2", 0xF000F850, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDM PC", 0x8000E810, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch LDMIA", 0x8000E8BD, ocsd.InstrBrIndirect, ocsd.SInstrV7ImpliedRet, 0},

		{"ISB", 0x8F6FF3BF, ocsd.InstrIsb, ocsd.SInstrNone, 0},
		{"DMB", 0x8F5FF3BF, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},
		{"DSB", 0x8F4FF3BF, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},

		{"CP15 ISB", 0x0F95EE07, ocsd.InstrIsb, ocsd.SInstrNone, 0},
		{"CP15 DMB", 0x0FBAEE07, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},
		{"CP15 DSB", 0x0F9AEE07, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},

		{"WFI T1", 0x0000BF20, ocsd.InstrWfiWfe, ocsd.SInstrNone, 0},
		{"WFI T2", 0x8002F3AF, ocsd.InstrWfiWfe, ocsd.SInstrNone, 0},

		{"Other", 0x00004400, ocsd.InstrOther, ocsd.SInstrNone, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkDecode(t, dec, ocsd.ArchV7, ocsd.ISAThumb2, tt)
		})
	}
}

func TestDecoder_DecodeA64(t *testing.T) {
	dec := NewDecoder()
	dec.SetAA64ErrOnBadOpcode(true)

	tests := []decodeCase{
		{"Direct Branch (B)", 0x14000000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch Link (BL)", 0x94000000, ocsd.InstrBr, ocsd.SInstrBrLink, 1},
		{"Direct Branch BC cond", 0x54000000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch CBZ", 0x34000000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch TBZ", 0x36000000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch CBB", 0x74000000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch CB reg", 0xF4000000, ocsd.InstrBr, ocsd.SInstrNone, 0},
		{"Direct Branch CB imm", 0x75000000, ocsd.InstrBr, ocsd.SInstrNone, 0},

		{"Indirect Branch (BR)", 0xD61F0000, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"Indirect Branch Link (BLR)", 0xD63F0000, ocsd.InstrBrIndirect, ocsd.SInstrBrLink, 1},
		{"RET", 0xD65F0000, ocsd.InstrBrIndirect, ocsd.SInstrV8Ret, 0},
		{"ERET", 0xD69F03E0, ocsd.InstrBrIndirect, ocsd.SInstrV8Eret, 0},
		{"BRAA (v8.3)", 0xD71F0800, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"BLRAA (v8.3)", 0xD73F0800, ocsd.InstrBrIndirect, ocsd.SInstrBrLink, 1},
		{"BRAAZ (v8.3)", 0xD61F081F, ocsd.InstrBrIndirect, ocsd.SInstrNone, 0},
		{"BLRAAZ (v8.3)", 0xD63F081F, ocsd.InstrBrIndirect, ocsd.SInstrBrLink, 1},
		{"RETAA (v8.3)", 0xD65F0BFF, ocsd.InstrBrIndirect, ocsd.SInstrV8Ret, 0},
		{"ERETAA (v8.3)", 0xD69F0BFF, ocsd.InstrBrIndirect, ocsd.SInstrV8Eret, 0},

		{"ISB", 0xD50330DF, ocsd.InstrIsb, ocsd.SInstrNone, 0},
		{"DMB", 0xD50330BF, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},
		{"DSB", 0xD503309F, ocsd.InstrDsbDmb, ocsd.SInstrNone, 0},

		{"WFI", 0xD503205F, ocsd.InstrWfiWfe, ocsd.SInstrNone, 0},
		{"WFIT/WFET (AA64)", 0xD5031000, ocsd.InstrWfiWfe, ocsd.SInstrNone, 0},
		{"TSTART", 0xD5233060, ocsd.InstrTstart, ocsd.SInstrNone, 0},

		{"Other", 0x8B000000, ocsd.InstrOther, ocsd.SInstrNone, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkDecode(t, dec, ocsd.ArchAA64, ocsd.ISAAArch64, tt)
		})
	}

	t.Run("Bad Opcode", func(t *testing.T) {
		info := &ocsd.InstrInfo{
			PeType:    ocsd.ArchProfile{Arch: ocsd.ArchAA64},
			ISA:       ocsd.ISAAArch64,
			InstrAddr: 0x1000,
			Opcode:    0x0000FFFF, // Top 16 bits are 0x0000
		}
		err := dec.DecodeInstruction(info)
		if err != ocsd.ErrInvalidOpcode {
			t.Errorf("Expected ErrInvalidOpcode, got %v", err)
		}
	})
}

func TestDecoder_HelperClassificationAndDestinations(t *testing.T) {
	dec := NewDecoder()
	dec.SetAA64ErrOnBadOpcode(true)

	info := &DecodeInfo{ArchVersion: ocsd.ArchV7}
	if !InstARMIsBranch(0xEA000000, info) || !InstThumbIsBranch(0xD0000000, info) || !InstA64IsBranch(0x14000000, info) {
		t.Fatalf("expected known opcodes to classify as branches")
	}
	if !InstARMIsUDF(0xe7f000f0) || !InstThumbIsUDF(0xde000000) || !InstThumbIsUDF(0xf7f0a000) || !InstA64IsUDF(0x00000000) {
		t.Fatalf("expected known UDF opcodes to classify as UDF")
	}
	if !InstA64IsUDF(0x00100000) || !InstA64IsUDF(0xffe00000) || InstA64IsUDF(0x8b000000) {
		t.Fatalf("unexpected A64 UDF range classification")
	}

	if InstThumbIsIT(0xbf000000) != 0 {
		t.Fatalf("unexpected IT block decoding")
	}

	var armDest uint32 = 0xDEADBEEF
	if got, ok := InstARMBranchDestination(0x1000, 0x0a000004); !ok || got == 0xDEADBEEF {
		t.Fatalf("expected ARM branch destination to be computed")
	}
	armDest = 0xCAFE
	if _, ok := InstARMBranchDestination(0x1000, 0xE0000000); ok || armDest != 0xCAFE {
		t.Fatalf("non-branch ARM opcode should not update destination")
	}

	if got, ok := InstThumbBranchDestination(0x1000, 0xd0000000); !ok || (got&1) == 0 {
		t.Fatalf("expected Thumb conditional branch destination with Thumb bit set")
	}
	if got, ok := InstThumbBranchDestination(0x1000, 0xf000c001); !ok || (got&1) == 0 {
		t.Fatalf("expected WLSTP Thumb destination")
	}

	var a64Dest uint64 = 0xABCDEF
	if !InstA64BranchDestination(0x1000, 0x54000000, &a64Dest) || a64Dest == 0xABCDEF {
		t.Fatalf("expected A64 branch destination to be computed")
	}
	a64Dest = 0xABCDEF
	if InstA64BranchDestination(0x1000, 0x8B000000, &a64Dest) || a64Dest != 0xABCDEF {
		t.Fatalf("non-branch A64 opcode should not update destination")
	}

	if InstARMBarrier(0x0e070f9a) != ArmBarrierDsb || InstARMBarrier(0xf5700060) != ArmBarrierIsb || InstThumbBarrier(0xf3bf8f50) != ArmBarrierDmb || InstA64Barrier(0xd503300f) != ArmBarrierNone {
		t.Fatalf("unexpected barrier classification")
	}

	unsuppInfo := &ocsd.InstrInfo{ISA: ocsd.ISATee}
	if err := dec.DecodeInstruction(unsuppInfo); err != ocsd.ErrUnsupportedISA {
		t.Fatalf("expected unsupported ISA error, got %v", err)
	}

	itThumb := &ocsd.InstrInfo{ISA: ocsd.ISAThumb2, Opcode: 0x00004400, TrackItBlock: 1, ThumbItConditions: 1}
	if err := dec.DecodeInstruction(itThumb); err != nil || itThumb.ThumbItConditions != 0 {
		t.Fatalf("expected IT condition decrement, err=%v cond=%d", err, itThumb.ThumbItConditions)
	}

	if !InstThumbIsBranchAndLink(0x47800000, info) || !InstThumbIsBranchAndLink(0xf000c000, info) || InstThumbIsBranchAndLink(0x00000000, info) {
		t.Fatalf("unexpected Thumb branch-link classification")
	}
	if !InstA64IsBranchAndLink(0xd63f0000, info) || !InstA64IsBranchAndLink(0x94000000, info) {
		t.Fatalf("expected A64 BLR/BL to classify as branch-link")
	}
	info.ArchVersion = ocsd.ArchV8r3
	if !InstA64IsBranchAndLink(0xd73f0800, info) || !InstA64IsBranchAndLink(0xd63f081F, info) || InstA64IsBranchAndLink(0x00000000, info) {
		t.Fatalf("unexpected A64 v8.3 branch-link classification")
	}

	if isBranch, _, _ := InstThumbIsDirectBranchLink(0xf00fc001, info); !isBranch {
		t.Fatalf("expected Thumb direct branch-link classification")
	}
	if isBranch, _, _ := InstThumbIsDirectBranchLink(0xf040c001, info); !isBranch {
		t.Fatalf("expected Thumb direct branch-link classification")
	}
	if isBranch, _ := InstA64IsIndirectBranchLink(0xd69f0bff, info); !isBranch {
		t.Fatalf("expected A64 indirect branch-link classification")
	}
	if isBranch, _ := InstA64IsIndirectBranchLink(0xd6ff03e0, info); !isBranch {
		t.Fatalf("expected A64 indirect branch-link classification")
	}
	if InstThumbIsUDF(0x00000000) {
		t.Fatalf("non-UDF Thumb opcode misclassified")
	}
}
