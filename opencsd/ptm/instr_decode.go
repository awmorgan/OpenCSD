package ptm

import (
	"encoding/binary"
	"fmt"

	"opencsd/common"
)

// InstrDecoder decodes ARM/Thumb instructions to determine branch behavior
type InstrDecoder struct {
	isa common.ISA
}

// NewInstrDecoder creates a new instruction decoder for the given ISA
func NewInstrDecoder(isa common.ISA) *InstrDecoder {
	return &InstrDecoder{isa: isa}
}

// DecodeInstruction decodes an instruction at the given address
// Returns instruction info and any error
func (d *InstrDecoder) DecodeInstruction(addr uint64, memAcc common.MemoryAccessor) (*common.InstrInfo, error) {
	info := common.NewInstrInfo()

	switch d.isa {
	case common.ISAARM:
		return d.decodeARM(addr, memAcc, info)
	case common.ISAThumb, common.ISAThumb2:
		return d.decodeThumb(addr, memAcc, info)
	default:
		return nil, fmt.Errorf("unsupported ISA: %s", d.isa)
	}
}

// DecodeARMOpcode decodes a 32-bit ARM instruction opcode without reading memory.
func (d *InstrDecoder) DecodeARMOpcode(addr uint64, opcode uint32) (*common.InstrInfo, error) {
	info := common.NewInstrInfo()
	info.Opcode = opcode
	info.Size = 4

	return d.decodeARMOpcode(addr, opcode, info), nil
}

// decodeARM decodes a 32-bit ARM instruction
func (d *InstrDecoder) decodeARM(addr uint64, memAcc common.MemoryAccessor, info *common.InstrInfo) (*common.InstrInfo, error) {
	buf := make([]byte, 4)
	n, err := memAcc.ReadMemory(addr, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read instruction at 0x%X: %w", addr, err)
	}
	if n < 4 {
		return nil, fmt.Errorf("incomplete instruction read at 0x%X: got %d bytes", addr, n)
	}

	// ARM is little-endian
	opcode := binary.LittleEndian.Uint32(buf)
	info.Opcode = opcode
	info.Size = 4

	return d.decodeARMOpcode(addr, opcode, info), nil
}

// decodeARMOpcode decodes a 32-bit ARM instruction opcode.
func (d *InstrDecoder) decodeARMOpcode(addr uint64, opcode uint32, info *common.InstrInfo) *common.InstrInfo {
	// Default: next ISA is same as current
	info.NextISA = d.isa
	info.NextISAValid = true

	// Extract condition field (bits 31-28)
	cond := (opcode >> 28) & 0xF

	// Check for unconditional instructions (cond == 0xF)
	if cond == 0xF {
		// Unconditional instruction space
		info.IsConditional = false
		// Check for BLX (immediate)
		if (opcode & 0xFE000000) == 0xFA000000 {
			info.IsBranch = true
			info.Type = common.InstrTypeBranch
			info.IsLink = true
			// BLX immediate always switches to Thumb
			info.NextISA = common.ISAThumb2
			// Calculate branch target
			offset := int32(opcode&0x00FFFFFF) << 2
			if (opcode & 0x01000000) != 0 {
				offset |= 2 // H bit for Thumb alignment
			}
			// Sign extend from 26 bits
			if offset&0x02000000 != 0 {
				offset |= ^int32(0x03FFFFFF)
			}
			info.BranchTarget = uint64(int64(addr) + int64(offset) + 8)
			info.HasBranchTarget = true
		}
		return info
	}

	// Conditional instructions
	if cond != 0xE { // 0xE = always (AL condition)
		info.IsConditional = true
	}

	// Check for branch instructions
	// B/BL: bits 27-25 = 101
	if (opcode & 0x0E000000) == 0x0A000000 {
		info.IsBranch = true
		info.Type = common.InstrTypeBranch
		if opcode&0x01000000 != 0 {
			info.IsLink = true
		}

		// Calculate branch offset (24-bit signed, shifted left by 2)
		offset := int32(opcode & 0x00FFFFFF)
		// Sign extend from 24 bits
		if offset&0x00800000 != 0 {
			offset |= ^int32(0x00FFFFFF)
		}
		offset <<= 2

		// Branch target = PC + offset + 8 (PC is 8 bytes ahead in ARM)
		info.BranchTarget = uint64(int64(addr) + int64(offset) + 8)
		info.HasBranchTarget = true
		return info
	}

	// BX/BLX (register): bits 27-4 = 0x012FFF, bits 7-4 determine BX(1) or BLX(3)
	if (opcode&0x0FFFFFF0) == 0x012FFF10 || (opcode&0x0FFFFFF0) == 0x012FFF30 {
		info.IsBranch = true
		info.Type = common.InstrTypeBranchIndirect
		info.HasBranchTarget = false // Register-based, can't determine statically
		if (opcode & 0x00000020) != 0 {
			info.IsLink = true
		}
		// Detect BX/BLX LR return (Rm == 14)
		rm := opcode & 0xF
		if rm == 0xE {
			info.IsReturn = true
		}
		return info
	}

	// LDM with PC in register list is an indirect branch (often a return)
	// LDM: bits 27-25 = 100, L bit (20) = 1
	if (opcode&0x0E000000) == 0x08000000 && (opcode&0x00100000) != 0 {
		regList := opcode & 0x0000FFFF
		if (regList & 0x8000) != 0 {
			info.IsBranch = true
			info.Type = common.InstrTypeBranchIndirect
			info.HasBranchTarget = false
			// Treat LDM SP!, {...,PC} as return
			rn := (opcode >> 16) & 0xF
			wback := (opcode & 0x00200000) != 0
			if rn == 0xD && wback {
				info.IsReturn = true
			}
			return info
		}
	}

	// LDR to PC is an indirect branch (often a return)
	// LDR: bits 27-26 = 01, L bit (20) = 1
	if (opcode&0x0C000000) == 0x04000000 && (opcode&0x00100000) != 0 {
		rd := (opcode >> 12) & 0xF
		if rd == 0xF {
			info.IsBranch = true
			info.Type = common.InstrTypeBranchIndirect
			info.HasBranchTarget = false
			rn := (opcode >> 16) & 0xF
			wback := (opcode & 0x00200000) != 0
			postIndex := (opcode & 0x01000000) == 0
			if rn == 0xD && (wback || postIndex) {
				info.IsReturn = true
			}
			return info
		}
	}

	// Not a branch - normal instruction
	info.Type = common.InstrTypeNormal
	info.IsBranch = false
	return info
}

// decodeThumb decodes a 16-bit or 32-bit Thumb instruction
func (d *InstrDecoder) decodeThumb(addr uint64, memAcc common.MemoryAccessor, info *common.InstrInfo) (*common.InstrInfo, error) {
	buf := make([]byte, 2)
	n, err := memAcc.ReadMemory(addr, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read instruction at 0x%X: %w", addr, err)
	}
	if n < 2 {
		return nil, fmt.Errorf("incomplete instruction read at 0x%X: got %d bytes", addr, n)
	}

	// Thumb is little-endian
	opcode16 := binary.LittleEndian.Uint16(buf)
	info.Opcode = uint32(opcode16)
	info.Size = 2

	// Check if this is a 32-bit Thumb2 instruction
	// Thumb2 instructions have bits 15-11 = 0b11101, 0b11110, or 0b11111
	if (opcode16 & 0xF800) >= 0xE800 {
		// Read second halfword
		buf2 := make([]byte, 2)
		n, err = memAcc.ReadMemory(addr+2, buf2)
		if err != nil {
			return nil, fmt.Errorf("failed to read Thumb2 second halfword at 0x%X: %w", addr+2, err)
		}
		if n < 2 {
			return nil, fmt.Errorf("incomplete Thumb2 instruction at 0x%X", addr)
		}

		opcode32 := (uint32(opcode16) << 16) | uint32(binary.LittleEndian.Uint16(buf2))
		info.Opcode = opcode32
		info.Size = 4

		// Decode Thumb2 branches
		return d.decodeThumb2Branch(addr, opcode32, info), nil
	}

	// 16-bit Thumb instruction
	// B (conditional): 1101 xxxx xxxx xxxx (bits 15-12 = 0xD, bits 11-8 != 0xE or 0xF)
	if (opcode16&0xF000) == 0xD000 && (opcode16&0x0F00) < 0x0E00 {
		info.IsBranch = true
		info.IsConditional = true
		info.Type = common.InstrTypeBranch

		// Sign-extend 8-bit offset, shift left by 1
		offset := int32(int8(opcode16 & 0xFF))
		offset <<= 1

		// Branch target = PC + offset + 4 (PC is 4 bytes ahead in Thumb)
		info.BranchTarget = uint64(int64(addr) + int64(offset) + 4)
		info.HasBranchTarget = true
		return info, nil
	}

	// B (unconditional): 1110 0xxx xxxx xxxx (bits 15-11 = 0b11100)
	if (opcode16 & 0xF800) == 0xE000 {
		info.IsBranch = true
		info.IsConditional = false
		info.Type = common.InstrTypeBranch

		// Sign-extend 11-bit offset, shift left by 1
		offset := int32(opcode16 & 0x07FF)
		if offset&0x0400 != 0 {
			offset |= ^int32(0x07FF)
		}
		offset <<= 1

		// Branch target = PC + offset + 4
		info.BranchTarget = uint64(int64(addr) + int64(offset) + 4)
		info.HasBranchTarget = true
		return info, nil
	}

	// BX/BLX (register): 010001 11 x xxxx xxx (bits 15-7)
	if (opcode16 & 0xFF00) == 0x4700 {
		info.IsBranch = true
		info.Type = common.InstrTypeBranchIndirect
		info.HasBranchTarget = false
		if (opcode16 & 0x0080) != 0 {
			info.IsLink = true
		}
		return info, nil
	}

	// Not a branch
	info.Type = common.InstrTypeNormal
	info.IsBranch = false
	return info, nil
}

// decodeThumb2Branch decodes a 32-bit Thumb2 branch instruction
func (d *InstrDecoder) decodeThumb2Branch(addr uint64, opcode uint32, info *common.InstrInfo) *common.InstrInfo {
	// Extract first and second halfwords
	hw1 := (opcode >> 16) & 0xFFFF
	hw2 := opcode & 0xFFFF

	// B (conditional): 1111 0xxx xxxx xxxx : 10x0 xxxx xxxx xxxx
	if (hw1&0xF800) == 0xF000 && (hw2&0xD000) == 0x8000 {
		info.IsBranch = true
		info.IsConditional = true
		info.Type = common.InstrTypeBranch

		// Extract offset bits
		s := (hw1 >> 10) & 1
		j1 := (hw2 >> 13) & 1
		j2 := (hw2 >> 11) & 1
		imm6 := hw1 & 0x3F
		imm11 := hw2 & 0x7FF

		// Combine offset: S:J2:J1:imm6:imm11:0
		offset := int32((s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1))

		// Sign extend from 21 bits
		if offset&0x00100000 != 0 {
			offset |= ^int32(0x001FFFFF)
		}

		info.BranchTarget = uint64(int64(addr) + int64(offset) + 4)
		info.HasBranchTarget = true
		return info
	}
	info.IsLink = true

	// B/BL (unconditional): 1111 0xxx xxxx xxxx : 11x1 xxxx xxxx xxxx
	if (hw1&0xF800) == 0xF000 && (hw2&0xD000) == 0xD000 {
		info.IsBranch = true
		info.IsConditional = false
		info.Type = common.InstrTypeBranch

		// Extract offset bits
		s := (hw1 >> 10) & 1
		j1 := (hw2 >> 13) & 1
		j2 := (hw2 >> 11) & 1
		imm10 := hw1 & 0x3FF
		imm11 := hw2 & 0x7FF

		// I1 = NOT(J1 XOR S), I2 = NOT(J2 XOR S)
		i1 := ((j1 ^ s) ^ 1) & 1
		i2 := ((j2 ^ s) ^ 1) & 1

		// Combine offset: S:I1:I2:imm10:imm11:0
		offset := int32((s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1))

		// Sign extend from 25 bits
		if offset&0x01000000 != 0 {
			offset |= ^int32(0x01FFFFFF)
		}

		info.BranchTarget = uint64(int64(addr) + int64(offset) + 4)
		info.HasBranchTarget = true
		return info
	}

	// Not a recognized branch
	info.Type = common.InstrTypeNormal
	info.IsBranch = false
	return info
}
