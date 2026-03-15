package ocsd

import (
	"strings"
	"testing"
)

func TestTraceElementString_AddressWidthFormatting(t *testing.T) {
	e := NewTraceElementWithType(GenElemInstrRange)
	e.SetAddrRange(0x1234, 0x123456789ABCDEF0, 1)
	e.SetISA(ISAArm)
	e.SetLastInstrInfo(true, InstrOther, SInstrNone, 4)

	s := e.String()
	want := "exec range=0x1234:[0x123456789abcdef0]"
	if !strings.Contains(s, want) {
		t.Fatalf("expected %q in %q", want, s)
	}
}

func TestTraceElementString_ExceptionRetAddressFormatting(t *testing.T) {
	e := NewTraceElementWithType(GenElemException)
	e.SetExcepRetAddr(true)
	e.EnAddr = 0xDEADBEEF
	e.SetExceptionNum(0x11)

	s := e.String()
	want := "pref ret addr:0xdeadbeef"
	if !strings.Contains(s, want) {
		t.Fatalf("expected %q in %q", want, s)
	}
}

func TestTraceElementString_AddrNaccMemSpaceFormatting(t *testing.T) {
	tests := []struct {
		name  string
		space MemSpaceAcc
		want  string
	}{
		{name: "EL2", space: MemSpaceEL2, want: "Memspace [0x4:EL2N]"},
		{name: "N", space: MemSpaceN, want: "Memspace [0x6:Any NS]"},
		{name: "Combo", space: MemSpaceEL1S | MemSpaceEL2, want: "Memspace [0x5:EL1S,EL2N]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewTraceElementWithType(GenElemAddrNacc)
			e.StAddr = 0x1000
			e.SetExceptionNum(uint32(tt.space))

			s := e.String()
			if !strings.Contains(s, tt.want) {
				t.Fatalf("expected %q in %q", tt.want, s)
			}
		})
	}
}
