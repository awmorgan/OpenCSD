package etmv3

import (
	"fmt"
	"opencsd/internal/ocsd"
	"strings"
)

// Config represents the hardware configuration for an ETMv3 trace macrocell.
// This interprets the standard ETMv3 configuration registers.
type Config struct {
	RegIDR   uint32
	RegCtrl  uint32
	RegCCER  uint32
	RegTrcID uint32
	ArchVer  ocsd.ArchVersion
	CoreProf ocsd.CoreProfile
}

// Register bit constants
const (
	ctrlDataAddr uint32 = 0x4
	ctrlDataVal  uint32 = 0x8
	ctrlCycleAcc uint32 = 0x1000
	ctrlDataOnly uint32 = 0x100000
	ctrlTsEna    uint32 = 0x1 << 28
	ctrlVmidEna  uint32 = 0x1 << 30

	ccerHasTs   uint32 = 0x1 << 22
	ccerVirtExt uint32 = 0x1 << 26
	ccerTs64Bit uint32 = 0x1 << 29

	idrAltBranch uint32 = 0x100000
)

// TraceMode defines the combination of trace data enabled
type TraceMode int

const (
	TMInstrOnly TraceMode = iota
	TMIDataVal
	TMIDataAddr
	TMIDataValAddr
	TMDataOnlyVal
	TMDataOnlyAddr
	TMDataOnlyValAddr
)

// TraceMode returns the effective trace mode based on the control register
func (c *Config) TraceMode() TraceMode {
	addr, val := c.DataAddrTrace(), c.DataValTrace()
	if c.InstrTrace() {
		return instrTraceMode(addr, val)
	}
	return dataOnlyTraceMode(addr, val)
}

func instrTraceMode(addr, val bool) TraceMode {
	switch {
	case addr && val:
		return TMIDataValAddr
	case addr:
		return TMIDataAddr
	case val:
		return TMIDataVal
	default:
		return TMInstrOnly
	}
}

func dataOnlyTraceMode(addr, val bool) TraceMode {
	switch {
	case addr && val:
		return TMDataOnlyValAddr
	case addr:
		return TMDataOnlyAddr
	default:
		return TMDataOnlyVal
	}
}

func (c *Config) InstrTrace() bool    { return (c.RegCtrl & ctrlDataOnly) == 0 }
func (c *Config) DataValTrace() bool  { return (c.RegCtrl & ctrlDataVal) != 0 }
func (c *Config) DataAddrTrace() bool { return (c.RegCtrl & ctrlDataAddr) != 0 }
func (c *Config) DataTrace() bool     { return (c.RegCtrl & (ctrlDataAddr | ctrlDataVal)) != 0 }

func (c *Config) CycleAcc() bool { return (c.RegCtrl & ctrlCycleAcc) != 0 }

func (c *Config) MinorRev() int { return int((c.RegIDR & 0xF0) >> 4) }

func (c *Config) V7MArch() bool {
	return c.ArchVer == ocsd.ArchV7 && c.CoreProf == ocsd.ProfileCortexM
}

func (c *Config) AltBranch() bool {
	return (c.RegIDR&idrAltBranch) != 0 && c.MinorRev() >= 4
}

var ctxtIDByteCounts = [...]int{0, 1, 2, 4}

func (c *Config) CtxtIDBytes() int {
	return ctxtIDByteCounts[(c.RegCtrl>>14)&0x3]
}

func (c *Config) HasVirtExt() bool { return (c.RegCCER & ccerVirtExt) != 0 }
func (c *Config) VMIDTrace() bool  { return (c.RegCtrl & ctrlVmidEna) != 0 }

func (c *Config) HasTS() bool     { return (c.RegCCER & ccerHasTs) != 0 }
func (c *Config) TSEnabled() bool { return (c.RegCtrl & ctrlTsEna) != 0 }
func (c *Config) TSPkt64() bool   { return (c.RegCCER & ccerTs64Bit) != 0 }

func (c *Config) TraceID() uint8 { return uint8(c.RegTrcID & 0x7F) }

// String returns a brief description of the config.
func (c *Config) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ETMv3 Config [ID=0x%02x, IDR=0x%08x, CTRL=0x%08x]", c.TraceID(), c.RegIDR, c.RegCtrl)
	return sb.String()
}
