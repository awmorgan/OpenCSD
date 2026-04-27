package ocsd

import (
	"strings"
	"testing"
)

func assertTraceElementStringContains(t *testing.T, e *TraceElement, want string) {
	t.Helper()
	if got := e.String(); !strings.Contains(got, want) {
		t.Fatalf("expected %q in %q", want, got)
	}
}

func TestTraceElementString_AddressWidthFormatting(t *testing.T) {
	e := NewTraceElementWithType(GenElemInstrRange)
	e.SetAddrRange(0x1234, 0x123456789ABCDEF0, 1)
	e.SetISA(ISAArm)
	e.SetLastInstrInfo(true, InstrOther, SInstrNone, 4)

	assertTraceElementStringContains(t, e, "exec range=0x1234:[0x123456789abcdef0]")
}

func TestTraceElementString_ExceptionRetAddressFormatting(t *testing.T) {
	e := NewTraceElementWithType(GenElemException)
	e.ExceptionRetAddr = true
	e.EndAddr = 0xDEADBEEF
	e.SetExceptionNum(0x11)

	assertTraceElementStringContains(t, e, "pref ret addr:0xdeadbeef")
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
			e.StartAddr = 0x1000
			e.SetExceptionNum(uint32(tt.space))

			assertTraceElementStringContains(t, e, tt.want)
		})
	}
}
