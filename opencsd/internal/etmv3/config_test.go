package etmv3

import (
	"strings"
	"testing"

	"opencsd/internal/ocsd"
)

func TestConfig(t *testing.T) {
	c := &Config{
		RegIDR:   0x4100F310,                                         // MinorRev = 1
		RegCtrl:  ctrlCycleAcc | ctrlTsEna | ctrlVmidEna | (2 << 14), // CtxtIDBytes = 2
		RegCCER:  ccerHasTs | ccerVirtExt | ccerTs64Bit,
		RegTrcID: 0x42,
		ArchVer:  ocsd.ArchV7,
		CoreProf: ocsd.ProfileCortexM,
	}

	if !c.IsInstrTrace() {
		t.Error("expected IsInstrTrace")
	}
	if c.IsDataValTrace() {
		t.Error("unexpected IsDataValTrace")
	}
	if c.IsDataAddrTrace() {
		t.Error("unexpected IsDataAddrTrace")
	}
	if c.IsDataTrace() {
		t.Error("unexpected IsDataTrace")
	}
	if c.TraceMode() != TMInstrOnly {
		t.Error("expected TMInstrOnly")
	}

	if !c.IsCycleAcc() {
		t.Error("expected IsCycleAcc")
	}
	if c.MinorRev() != 1 {
		t.Error("expected Minor rev 1")
	}
	if !c.IsV7MArch() {
		t.Error("expected V7M")
	}
	if c.IsAltBranch() {
		t.Error("unexpected IsAltBranch")
	}
	if c.CtxtIDBytes() != 2 {
		t.Error("expected CtxtIDBytes=2")
	}
	if !c.HasVirtExt() {
		t.Error("expected HasVirtExt")
	}
	if !c.IsVMIDTrace() {
		t.Error("expected IsVMIDTrace")
	}
	if !c.HasTS() {
		t.Error("expected HasTS")
	}
	if !c.IsTSEnabled() {
		t.Error("expected IsTSEnabled")
	}
	if !c.TSPkt64() {
		t.Error("expected TSPkt64")
	}
	if c.TraceID() != 0x42 {
		t.Error("expected 0x42 TraceID")
	}

	str := c.String()
	if !strings.Contains(str, "ETMv3 Config") {
		t.Error("String() format incorrect")
	}

	// Test TraceMode variations
	c.RegCtrl |= ctrlDataOnly
	if c.TraceMode() != TMDataOnlyVal {
		t.Error("expected TMDataOnlyVal")
	}
	c.RegCtrl |= ctrlDataAddr
	if c.TraceMode() != TMDataOnlyAddr {
		t.Error("expected TMDataOnlyAddr")
	}
	c.RegCtrl |= ctrlDataVal
	if c.TraceMode() != TMDataOnlyValAddr {
		t.Error("expected TMDataOnlyValAddr")
	}
	c.RegCtrl &^= ctrlDataAddr
	if c.TraceMode() != TMDataOnlyVal {
		t.Error("expected TMDataOnlyVal")
	}

	c.RegCtrl &^= ctrlDataOnly // back to instr+data
	if c.TraceMode() != TMIDataVal {
		t.Error("expected TMIDataVal")
	}
	c.RegCtrl |= ctrlDataAddr
	if c.TraceMode() != TMIDataValAddr {
		t.Error("expected TMIDataValAddr")
	}
	c.RegCtrl &^= ctrlDataVal
	if c.TraceMode() != TMIDataAddr {
		t.Error("expected TMIDataAddr")
	}

	// CtxtIDBytes edge cases
	c.RegCtrl = (1 << 14)
	if c.CtxtIDBytes() != 1 {
		t.Error("expected 1")
	}
	c.RegCtrl = (3 << 14)
	if c.CtxtIDBytes() != 4 {
		t.Error("expected 4")
	}
	c.RegCtrl = 0
	if c.CtxtIDBytes() != 0 {
		t.Error("expected 0")
	}

	// IsAltBranch
	c.RegIDR = idrAltBranch | (4 << 4)
	if !c.IsAltBranch() {
		t.Error("expected IsAltBranch")
	}
}
