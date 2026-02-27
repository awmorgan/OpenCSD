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

// NewConfig returns a default configuration for PTM.
func NewConfig() *Config {
	return &Config{
		ConfigRegs: ConfigRegs{
			ArchVer:  ocsd.ArchV7,
			CoreProf: ocsd.ProfileCortexA,
			RegCCER:  0,
			RegIDR:   0x4100F310, // defaults set ETMv1.1, V7A
			RegCtrl:  0,
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

func (c *Config) EnaBranchBCast() bool {
	return (c.RegCtrl & ctrlBranchBcast) != 0
}

func (c *Config) EnaCycleAcc() bool {
	return (c.RegCtrl & ctrlCycleAcc) != 0
}

func (c *Config) EnaRetStack() bool {
	return (c.RegCtrl & ctrlRetStackEna) != 0
}

func (c *Config) HasRetStack() bool {
	return (c.RegCCER & ccerRestackImpl) != 0
}

func (c *Config) MinorRev() int {
	return int(c.RegIDR&0xF0) >> 4
}

func (c *Config) HasTS() bool {
	return (c.RegCCER & ccerTSImpl) != 0
}

func (c *Config) EnaTS() bool {
	return (c.RegCtrl & ctrlTSEna) != 0
}

func (c *Config) TSPkt64() bool {
	if c.MinorRev() == 0 {
		return false
	}
	return (c.RegCCER & ccerTS64Bit) != 0
}

func (c *Config) TSBinEnc() bool {
	if c.MinorRev() == 0 {
		return false
	}
	return (c.RegCCER & ccerTSEncNat) != 0
}

func (c *Config) CtxtIDBytes() int {
	ctxtIdSizes := []int{0, 1, 2, 4}
	return ctxtIdSizes[(c.RegCtrl>>14)&0x3]
}

func (c *Config) HasVirtExt() bool {
	return (c.RegCCER & ccerVirtExt) != 0
}

func (c *Config) EnaVMID() bool {
	return (c.RegCtrl & ctrlVMIDEna) != 0
}

func (c *Config) DmsbGenTS() bool {
	return (c.RegCCER & ccerTSDmsb) != 0
}

func (c *Config) DmsbWayPt() bool {
	return (c.RegCCER & ccerDmsbWpt) != 0
}

func (c *Config) TraceID() uint8 {
	return uint8(c.RegTrcID & 0x7F)
}
