package ptm

import (
	"testing"

	"opencsd/common"
)

func TestInstrDecoder_ARM_Branch(t *testing.T) {
	// Create a simple memory buffer with a B (branch) instruction
	// B #0x38 instruction: 0x0E0000EA (ARM encoding: cond=E, opcode=0xA, offset=0x0E)
	// In little-endian: 0xEA, 0x00, 0x00, 0x0E
	memBuf := common.NewMemoryBuffer(0x80000000, []byte{0x0E, 0x00, 0x00, 0xEA})

	decoder := NewInstrDecoder(common.ISAARM)
	info, err := decoder.DecodeInstruction(0x80000000, memBuf)
	if err != nil {
		t.Fatalf("DecodeInstruction failed: %v", err)
	}

	if !info.IsBranch {
		t.Errorf("Expected instruction to be a branch, opcode=0x%08X", info.Opcode)
	}

	if info.Type != common.InstrTypeBranch {
		t.Errorf("Expected type Branch, got %s", info.Type)
	}

	if info.Size != 4 {
		t.Errorf("Expected size 4, got %d", info.Size)
	}

	if !info.HasBranchTarget {
		t.Error("Expected branch to have target")
	}

	// Branch target = PC + (offset << 2) + 8
	// PC = 0x80000000, offset = 0x0E << 2 = 56, + 8 = 64
	expectedTarget := uint64(0x80000000 + 56 + 8)
	if info.BranchTarget != expectedTarget {
		t.Errorf("Expected branch target 0x%X, got 0x%X", expectedTarget, info.BranchTarget)
	}

	t.Logf("Decoded ARM branch: target=0x%X, size=%d", info.BranchTarget, info.Size)
}

func TestInstrDecoder_ARM_Normal(t *testing.T) {
	// Create a memory buffer with a normal instruction
	// MOV r0, #0 = E3 A0 00 00 (little-endian)
	memBuf := common.NewMemoryBuffer(0x80000000, []byte{0x00, 0x00, 0xA0, 0xE3})

	decoder := NewInstrDecoder(common.ISAARM)
	info, err := decoder.DecodeInstruction(0x80000000, memBuf)
	if err != nil {
		t.Fatalf("DecodeInstruction failed: %v", err)
	}

	if info.IsBranch {
		t.Error("Expected instruction to not be a branch")
	}

	if info.Type != common.InstrTypeNormal {
		t.Errorf("Expected type Normal, got %s", info.Type)
	}

	if info.Size != 4 {
		t.Errorf("Expected size 4, got %d", info.Size)
	}

	t.Logf("Decoded ARM normal instruction: type=%s, size=%d", info.Type, info.Size)
}

func TestInstrDecoder_Thumb_Branch(t *testing.T) {
	// Thumb unconditional branch: E0 00 = B <offset>
	// offset = 0 (relative to PC+4)
	memBuf := common.NewMemoryBuffer(0x80000000, []byte{0x00, 0xE0})

	decoder := NewInstrDecoder(common.ISAThumb)
	info, err := decoder.DecodeInstruction(0x80000000, memBuf)
	if err != nil {
		t.Fatalf("DecodeInstruction failed: %v", err)
	}

	if !info.IsBranch {
		t.Error("Expected instruction to be a branch")
	}

	if info.Type != common.InstrTypeBranch {
		t.Errorf("Expected type Branch, got %s", info.Type)
	}

	if info.Size != 2 {
		t.Errorf("Expected size 2, got %d", info.Size)
	}

	if !info.HasBranchTarget {
		t.Error("Expected branch to have target")
	}

	// Branch target = PC + offset + 4 = 0x80000000 + 0 + 4
	expectedTarget := uint64(0x80000004)
	if info.BranchTarget != expectedTarget {
		t.Errorf("Expected branch target 0x%X, got 0x%X", expectedTarget, info.BranchTarget)
	}

	t.Logf("Decoded Thumb branch: target=0x%X, size=%d", info.BranchTarget, info.Size)
}

func TestInstrDecoder_RealTraceInstructions(t *testing.T) {
	// Load actual memory from trace_cov_a15 snapshot
	memMap := common.NewMultiRegionMemory()

	// Add CODE region
	codeData := []byte{
		0x64, 0x29, 0x00, 0xF0, // 0x80000278: instruction from real trace
		0x00, 0x00, 0xA0, 0xE3, // 0x8000027C: MOV r0, #0
		0x01, 0x10, 0xA0, 0xE3, // 0x80000280: MOV r1, #1
	}
	memMap.AddRegion(common.NewMemoryBuffer(0x80000278, codeData))

	decoder := NewInstrDecoder(common.ISAARM)
	info, err := decoder.DecodeInstruction(0x80000278, memMap)
	if err != nil {
		t.Fatalf("DecodeInstruction failed: %v", err)
	}

	t.Logf("Decoded instruction at 0x80000278:")
	t.Logf("  Type: %s", info.Type)
	t.Logf("  IsBranch: %v", info.IsBranch)
	t.Logf("  Size: %d", info.Size)
	t.Logf("  Opcode: 0x%08X", info.Opcode)
	if info.HasBranchTarget {
		t.Logf("  BranchTarget: 0x%X", info.BranchTarget)
	}
}
