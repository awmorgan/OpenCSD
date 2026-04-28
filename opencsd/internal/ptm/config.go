package ptm

import (
	"opencsd/internal/ocsd"
)

// ConfigRegs represents the PTM hardware configuration registers.
type ConfigRegs struct {
	RegIDR   uint32
	RegCtrl  uint32
	RegCCER  uint32
	RegTrcID uint32
	ArchVer  ocsd.ArchVersion
	CoreProf ocsd.CoreProfile
}

// Config represents the trace capture time configuration of a PTM hardware component.
type Config struct {
	ConfigRegs
}

const defaultRegIDR = 0x4100F310 // defaults set ETMv1.1, V7A

var ctxtIDByteSizes = [...]int{0, 1, 2, 4}

// NewConfig returns a default configuration for PTM.
func NewConfig() *Config {
	return &Config{
		ConfigRegs: ConfigRegs{
			ArchVer:  ocsd.ArchV7,
			CoreProf: ocsd.ProfileCortexA,
			RegIDR:   defaultRegIDR,
		},
	}
}

// register bit constants.
const (
	ctrlBranchBcast = 1 << 8
	ctrlCycleAcc    = 1 << 12
	ctrlTSEna       = 1 << 28
	ctrlRetStackEna = 1 << 29
	ctrlVMIDEna     = 1 << 30

	ccerTSImpl      = 1 << 22
	ccerRestackImpl = 1 << 23
	ccerDmsbWpt     = 1 << 24
	ccerTSDmsb      = 1 << 25
	ccerVirtExt     = 1 << 26
	ccerTSEncNat    = 1 << 28
	ccerTS64Bit     = 1 << 29
)

func (c *Config) ctrlEnabled(mask uint32) bool {
	return c.RegCtrl&mask != 0
}

func (c *Config) ccerEnabled(mask uint32) bool {
	return c.RegCCER&mask != 0
}

func (c *Config) EnaBranchBCast() bool {
	return c.ctrlEnabled(ctrlBranchBcast)
}

func (c *Config) EnaCycleAcc() bool {
	return c.ctrlEnabled(ctrlCycleAcc)
}

func (c *Config) EnaRetStack() bool {
	return c.ctrlEnabled(ctrlRetStackEna)
}

func (c *Config) HasRetStack() bool {
	return c.ccerEnabled(ccerRestackImpl)
}

func (c *Config) MinorRev() int {
	return int(c.RegIDR&0xF0) >> 4
}

func (c *Config) HasTS() bool {
	return c.ccerEnabled(ccerTSImpl)
}

func (c *Config) EnaTS() bool {
	return c.ctrlEnabled(ctrlTSEna)
}

func (c *Config) supportsPostMinor0Features() bool {
	return c.MinorRev() != 0
}

func (c *Config) TSPkt64() bool {
	return c.supportsPostMinor0Features() && c.ccerEnabled(ccerTS64Bit)
}

func (c *Config) TSBinEnc() bool {
	return c.supportsPostMinor0Features() && c.ccerEnabled(ccerTSEncNat)
}

func (c *Config) CtxtIDBytes() int {
	return ctxtIDByteSizes[(c.RegCtrl>>14)&0x3]
}

func (c *Config) HasVirtExt() bool {
	return c.ccerEnabled(ccerVirtExt)
}

func (c *Config) EnaVMID() bool {
	return c.ctrlEnabled(ctrlVMIDEna)
}

func (c *Config) DmsbGenTS() bool {
	return c.ccerEnabled(ccerTSDmsb)
}

func (c *Config) DmsbWayPt() bool {
	return c.ccerEnabled(ccerDmsbWpt)
}

func (c *Config) TraceID() uint8 {
	return uint8(c.RegTrcID & 0x7F)
}
