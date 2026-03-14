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
