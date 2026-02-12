package common

import (
	"testing"
)

func TestTraceElement_ToString(t *testing.T) {
	tests := []struct {
		name     string
		elem     TraceElement
		expected string
	}{
		{
			name: "Trace On",
			elem: TraceElement{
				ElemType: ElemTraceOn,
			},
			expected: "Trace On",
		},
		{
			name: "No Sync",
			elem: TraceElement{
				ElemType: ElemNoSync,
			},
			expected: "No Sync",
		},
		{
			name: "PE Context - EL1 NS",
			elem: TraceElement{
				ElemType: ElemPeContext,
				Context: PeContext{
					ExceptionLevel: EL1,
					SecurityLevel:  SecNonSecure,
					VMID:           0x123,
					ContextID:      0xABC,
				},
			},
			// C++ Format: "PE Context: EL<N>; <S/NS>; VMID:<hex>; CID:<hex>"
			expected: "PE Context: EL1; NS; VMID:0x123; CID:0xABC",
		},
		{
			name: "PE Context - EL3 Secure",
			elem: TraceElement{
				ElemType: ElemPeContext,
				Context: PeContext{
					ExceptionLevel: EL3,
					SecurityLevel:  SecSecure,
					VMID:           0x0,
					ContextID:      0x0,
				},
			},
			expected: "PE Context: EL3; S; VMID:0x0; CID:0x0",
		},
		{
			name: "Instruction Range - A64",
			elem: TraceElement{
				ElemType: ElemInstrRange,
				StAddr:   0x1000,
				EnAddr:   0x1010,
				ISA:      IsaA64,
			},
			// C++ Format: "I_Range: <Start> - <End>; <ISA>"
			expected: "I_Range: 0x1000 - 0x1010; A64",
		},
		{
			name: "Instruction Range - Thumb",
			elem: TraceElement{
				ElemType: ElemInstrRange,
				StAddr:   0x200,
				EnAddr:   0x204,
				ISA:      IsaThumb,
			},
			expected: "I_Range: 0x200 - 0x204; Thumb",
		},
		{
			name: "Exception",
			elem: TraceElement{
				ElemType: ElemException,
				ExcepID:  0x15, // Syscall or similar
			},
			expected: "Exception: ID 0x15",
		},
		{
			name: "Exception Return",
			elem: TraceElement{
				ElemType: ElemExceptionRet,
			},
			expected: "Exception Return",
		},
		{
			name: "Timestamp",
			elem: TraceElement{
				ElemType:  ElemTimestamp,
				Timestamp: 123456789,
			},
			expected: "Timestamp: 123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.elem.ToString()
			if got != tt.expected {
				t.Errorf("ToString() = %q, want %q", got, tt.expected)
			}
		})
	}
}
