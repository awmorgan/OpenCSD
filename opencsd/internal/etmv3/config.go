package etmv3

import (
	"fmt"
	"opencsd/internal/ocsd"
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
	ctrlDataVal  uint32 = 0x4
	ctrlDataAddr uint32 = 0x8
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
	if c.IsInstrTrace() {
		if c.IsDataAddrTrace() && c.IsDataValTrace() {
			return TMIDataValAddr
		}
		if c.IsDataAddrTrace() {
			return TMIDataAddr
		}
		if c.IsDataValTrace() {
			return TMIDataVal
		}
		return TMInstrOnly
	}
	if c.IsDataAddrTrace() && c.IsDataValTrace() {
		return TMDataOnlyValAddr
	}
	if c.IsDataAddrTrace() {
		return TMDataOnlyAddr
	}
	return TMDataOnlyVal
}

func (c *Config) IsInstrTrace() bool    { return (c.RegCtrl & ctrlDataOnly) == 0 }
func (c *Config) IsDataValTrace() bool  { return (c.RegCtrl & ctrlDataVal) != 0 }
func (c *Config) IsDataAddrTrace() bool { return (c.RegCtrl & ctrlDataAddr) != 0 }
func (c *Config) IsDataTrace() bool     { return (c.RegCtrl & (ctrlDataAddr | ctrlDataVal)) != 0 }

func (c *Config) IsCycleAcc() bool { return (c.RegCtrl & ctrlCycleAcc) != 0 }

func (c *Config) MinorRev() int { return int((c.RegIDR & 0xF0) >> 4) }

func (c *Config) IsV7MArch() bool {
	return c.ArchVer == ocsd.ArchV7 && c.CoreProf == ocsd.ProfileCortexM
}

func (c *Config) IsAltBranch() bool {
	return (c.RegIDR&idrAltBranch) != 0 && c.MinorRev() >= 4
}

func (c *Config) CtxtIDBytes() int {
	switch (c.RegCtrl >> 14) & 0x3 {
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 4
	default:
		return 0
	}
}

func (c *Config) HasVirtExt() bool  { return (c.RegCCER & ccerVirtExt) != 0 }
func (c *Config) IsVMIDTrace() bool { return (c.RegCtrl & ctrlVmidEna) != 0 }

func (c *Config) HasTS() bool       { return (c.RegCCER & ccerHasTs) != 0 }
func (c *Config) IsTSEnabled() bool { return (c.RegCtrl & ctrlTsEna) != 0 }
func (c *Config) TSPkt64() bool     { return (c.RegCCER & ccerTs64Bit) != 0 }

func (c *Config) TraceID() uint8 { return uint8(c.RegTrcID & 0x7F) }

// String returns a brief description of the config.
func (c *Config) String() string {
	return fmt.Sprintf("ETMv3 Config [ID=0x%02x, IDR=0x%08x, CTRL=0x%08x]", c.TraceID(), c.RegIDR, c.RegCtrl)
}
