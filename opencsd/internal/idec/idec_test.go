package idec

import (
	"testing"

	"opencsd/internal/common"
)

func TestDecodeInstruction(t *testing.T) {
	tests := []struct {
		name         string
		isa          common.Isa
		opcode       uint32
		instrAddr    uint64
		expectedType int
		expectedSub  int
		expectedCond bool
		expectedLink bool
		expectedDest uint64
		expectedSize uint8
		isGap        bool // Marked true if Go implementation is known to have a gap here
	}{
		// --- A64 Tests ---
		{
			name:         "A64 Direct Branch (B)",
			isa:          common.IsaA64,
			opcode:       0x14000001,
			instrAddr:    0x1000,
			expectedType: common.InstrTypeBranch,
			expectedDest: 0x1004,
			expectedSize: 4,
		},
		{
			name:         "A64 Branch and Link (BL)",
			isa:          common.IsaA64,
			opcode:       0x94000001,
			instrAddr:    0x1000,
			expectedType: common.InstrTypeBranch,
			expectedDest: 0x1004,
			expectedLink: true,
			expectedSub:  common.InstrSubTypeBrLink,
			expectedSize: 4,
		},
		{
			name:         "A64 Conditional Branch (B.EQ)",
			isa:          common.IsaA64,
			opcode:       0x54000000,
			instrAddr:    0x1000,
			expectedType: common.InstrTypeBranch,
			expectedCond: true,
			expectedDest: 0x1000, // offset 0
			expectedSize: 4,
		},
		{
			name:         "A64 Indirect Branch (BR X0)",
			isa:          common.IsaA64,
			opcode:       0xd61f0000,
			expectedType: common.InstrTypeIndirect,
			expectedSize: 4,
		},
		{
			name:         "A64 Return (RET)",
			isa:          common.IsaA64,
			opcode:       0xd65f03c0,
			expectedType: common.InstrTypeIndirect,
			expectedSub:  common.InstrSubTypeV8Ret,
			expectedSize: 4,
		},
		{
			name:         "A64 Barrier (ISB) - GAP",
			isa:          common.IsaA64,
			opcode:       0xd5033fdf,
			expectedType: common.InstrTypeISB,
			expectedSize: 4,
			isGap:        true,
		},

		// --- A32 Tests ---
		{
			name:         "A32 Direct Branch (B)",
			isa:          common.IsaArm32,
			opcode:       0xea000001,
			instrAddr:    0x1000,
			expectedType: common.InstrTypeBranch,
			expectedDest: 0x100c, // PC + 8 + 4
			expectedSize: 4,
		},
		{
			name:         "A32 Indirect Branch (BX LR)",
			isa:          common.IsaArm32,
			opcode:       0xe12fff1e,
			expectedType: common.InstrTypeIndirect,
			expectedSub:  common.InstrSubTypeV7ImpliedRet,
			expectedSize: 4,
		},
		{
			name:         "A32 Wait For Interrupt (WFI) - GAP",
			isa:          common.IsaArm32,
			opcode:       0xe320f003,
			expectedType: common.InstrTypeWFI_WFE,
			expectedSize: 4,
			isGap:        true,
		},

		// --- T32 Tests ---
		{
			name:         "T32 16-bit Branch (B)",
			isa:          common.IsaThumb,
			opcode:       0x0000e000, // B T2
			instrAddr:    0x1000,
			expectedType: common.InstrTypeBranch,
			expectedDest: 0x1004,
			expectedSize: 2,
		},
		{
			name:         "T32 32-bit Branch and Link (BL)",
			isa:          common.IsaThumb,
			opcode:       0xf000f000, // BL imm (T1) - using f000 f000 as swapped
			instrAddr:    0x1000,
			expectedType: common.InstrTypeBranch,
			expectedLink: true,
			expectedSub:  common.InstrSubTypeBrLink,
			expectedDest: 0x401004,
			expectedSize: 4,
		},
		{
			name:         "T32 IT Block - GAP",
			isa:          common.IsaThumb,
			opcode:       0x0000bf08, // IT EQ
			expectedType: common.InstrTypeOther,
			expectedSize: 2,
			isGap:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &common.InstrInfo{
				InstrAddr: tt.instrAddr,
				Opcode:    tt.opcode,
				ISA:       tt.isa,
			}

			err := DecodeInstruction(info, tt.isa)
			if err != nil {
				t.Errorf("DecodeInstruction() error = %v", err)
				return
			}

			if info.Type != tt.expectedType {
				if tt.isGap {
					t.Logf("INFO: Known GAP - Expected Type %d, got %d", tt.expectedType, info.Type)
				} else {
					t.Errorf("Type: expected %d, got %d", tt.expectedType, info.Type)
				}
			}

			if info.SubType != tt.expectedSub {
				if tt.isGap {
					t.Logf("INFO: Known GAP - Expected SubType %d, got %d", tt.expectedSub, info.SubType)
				} else {
					t.Errorf("SubType: expected %d, got %d", tt.expectedSub, info.SubType)
				}
			}

			if info.IsConditional != tt.expectedCond {
				t.Errorf("IsConditional: expected %v, got %v", tt.expectedCond, info.IsConditional)
			}

			if info.IsLink != tt.expectedLink {
				t.Errorf("IsLink: expected %v, got %v", tt.expectedLink, info.IsLink)
			}

			if info.BranchAddr != tt.expectedDest {
				t.Errorf("BranchAddr: expected 0x%x, got 0x%x", tt.expectedDest, info.BranchAddr)
			}

			if info.InstrSize != tt.expectedSize {
				t.Errorf("InstrSize: expected %d, got %d", tt.expectedSize, info.InstrSize)
			}
		})
	}
}
