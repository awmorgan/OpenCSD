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

	if !c.InstrTrace() {
		t.Error("expected InstrTrace")
	}
	if c.DataValTrace() {
		t.Error("unexpected DataValTrace")
	}
	if c.DataAddrTrace() {
		t.Error("unexpected DataAddrTrace")
	}
	if c.DataTrace() {
		t.Error("unexpected DataTrace")
	}
	if c.TraceMode() != TMInstrOnly {
		t.Error("expected TMInstrOnly")
	}

	if !c.CycleAcc() {
		t.Error("expected CycleAcc")
	}
	if c.MinorRev() != 1 {
		t.Error("expected Minor rev 1")
	}
	if !c.V7MArch() {
		t.Error("expected V7M")
	}
	if c.AltBranch() {
		t.Error("unexpected AltBranch")
	}
	if c.CtxtIDBytes() != 2 {
		t.Error("expected CtxtIDBytes=2")
	}
	if !c.HasVirtExt() {
		t.Error("expected HasVirtExt")
	}
	if !c.VMIDTrace() {
		t.Error("expected VMIDTrace")
	}
	if !c.HasTS() {
		t.Error("expected HasTS")
	}
	if !c.TSEnabled() {
		t.Error("expected TSEnabled")
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

	// AltBranch
	c.RegIDR = idrAltBranch | (4 << 4)
	if !c.AltBranch() {
		t.Error("expected AltBranch")
	}
}
