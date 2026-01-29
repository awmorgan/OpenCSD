package common

import (
	"strings"
	"testing"
)

func TestElemTypeString(t *testing.T) {
	tests := []struct {
		elemType ElemType
		expected string
	}{
		{ElemTypePeContext, "PE_CONTEXT"},
		{ElemTypeAddrRange, "ADDR_RANGE"},
		{ElemTypeException, "EXCEPTION"},
		{ElemTypeExceptionReturn, "EXCEPTION_RETURN"},
		{ElemTypeTimestamp, "TIMESTAMP"},
		{ElemTypeNoSync, "NO_SYNC"},
		{ElemTypeTraceOn, "TRACE_ON"},
		{ElemTypeEOTrace, "EO_TRACE"},
		{ElemTypeUnknown, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.elemType.String()
			if got != tt.expected {
				t.Errorf("ElemType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestISAString(t *testing.T) {
	tests := []struct {
		isa      ISA
		expected string
	}{
		{ISAARM, "ARM(32)"},
		{ISAThumb2, "Thumb2"},
		{ISAThumb, "Thumb"},
		{ISATEE, "TEE"},
		{ISAA64, "AArch64"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.isa.String()
			if got != tt.expected {
				t.Errorf("ISA.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSecurityStateString(t *testing.T) {
	tests := []struct {
		state    SecurityState
		expected string
	}{
		{SecurityStateSecure, "S"},
		{SecurityStateNonSecure, "N"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.state.String()
			if got != tt.expected {
				t.Errorf("SecurityState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExceptionLevelString(t *testing.T) {
	tests := []struct {
		level    ExceptionLevel
		expected string
	}{
		{EL0, "EL0"},
		{EL1, "EL1"},
		{EL2, "EL2"},
		{EL3, "EL3"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.level.String()
			if got != tt.expected {
				t.Errorf("ExceptionLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewGenericTraceElement(t *testing.T) {
	elem := NewGenericTraceElement(ElemTypePeContext)
	if elem.Type != ElemTypePeContext {
		t.Errorf("NewGenericTraceElement() Type = %v, want %v", elem.Type, ElemTypePeContext)
	}
}

func TestGenericTraceElement_Description_PEContext(t *testing.T) {
	elem := &GenericTraceElement{
		Type: ElemTypePeContext,
		Context: PEContext{
			ContextID:      0x12345678,
			VMID:           0x42,
			ISA:            ISAARM,
			SecurityState:  SecurityStateNonSecure,
			ExceptionLevel: EL1,
		},
	}

	desc := elem.Description()
	if !strings.Contains(desc, "PE_CONTEXT") {
		t.Errorf("Description should contain PE_CONTEXT, got: %s", desc)
	}
	if !strings.Contains(desc, "0x12345678") {
		t.Errorf("Description should contain context ID, got: %s", desc)
	}
}

func TestGenericTraceElement_Description_AddrRange(t *testing.T) {
	elem := &GenericTraceElement{
		Type: ElemTypeAddrRange,
		AddrRange: AddrRange{
			StartAddr:   0x80000000,
			EndAddr:     0x80000010,
			ISA:         ISAThumb2,
			NumInstr:    4,
			LastInstrSz: 4,
		},
	}

	desc := elem.Description()
	if !strings.Contains(desc, "ADDR_RANGE") {
		t.Errorf("Description should contain ADDR_RANGE, got: %s", desc)
	}
	if !strings.Contains(desc, "0x80000000") {
		t.Errorf("Description should contain start address, got: %s", desc)
	}
}

func TestGenericTraceElement_Description_Exception(t *testing.T) {
	elem := &GenericTraceElement{
		Type: ElemTypeException,
		Exception: ExceptionInfo{
			Number:      0x01,
			Type:        "Debug Halt",
			PrefRetAddr: 0x80000504,
		},
	}

	desc := elem.Description()
	if !strings.Contains(desc, "EXCEPTION") {
		t.Errorf("Description should contain EXCEPTION, got: %s", desc)
	}
	if !strings.Contains(strings.ToLower(desc), "0x1") {
		t.Errorf("Description should contain exception number, got: %s", desc)
	}
}

func TestGenericTraceElement_Description_ExceptionReturn(t *testing.T) {
	elem := &GenericTraceElement{
		Type: ElemTypeExceptionReturn,
	}

	desc := elem.Description()
	if desc != "EXCEPTION_RETURN" {
		t.Errorf("Description = %v, want EXCEPTION_RETURN", desc)
	}
}

func TestGenericTraceElement_Description_Timestamp(t *testing.T) {
	elem := &GenericTraceElement{
		Type:      ElemTypeTimestamp,
		Timestamp: 0x123456789ABC,
	}

	desc := elem.Description()
	if !strings.Contains(desc, "TIMESTAMP") {
		t.Errorf("Description should contain TIMESTAMP, got: %s", desc)
	}
	if !strings.Contains(desc, "0x123456789abc") {
		t.Errorf("Description should contain timestamp value, got: %s", desc)
	}
}

func TestGenericTraceElement_Description_TraceOn(t *testing.T) {
	elem := &GenericTraceElement{
		Type:          ElemTypeTraceOn,
		TraceOnReason: "debug restart",
	}

	desc := elem.Description()
	if !strings.Contains(desc, "TRACE_ON") {
		t.Errorf("Description should contain TRACE_ON, got: %s", desc)
	}
	if !strings.Contains(desc, "debug restart") {
		t.Errorf("Description should contain reason, got: %s", desc)
	}
}

func TestGenericTraceElement_Description_EOTrace(t *testing.T) {
	elem := &GenericTraceElement{
		Type: ElemTypeEOTrace,
	}

	desc := elem.Description()
	if desc != "END_OF_TRACE" {
		t.Errorf("Description = %v, want END_OF_TRACE", desc)
	}
}
