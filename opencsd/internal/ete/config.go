package ete

import (
	"opencsd/internal/etmv4"
	"opencsd/internal/ocsd"
)

const (
	defaultIDR0    uint32 = 0x28000EA1
	defaultIDR1    uint32 = 0x4100FFF3
	defaultIDR2    uint32 = 0x00000488
	defaultIDR8    uint32 = 0x00000000
	defaultConfigR uint32 = 0x000000C1
	defaultDevArch uint32 = 0x47705A13

	devArchMajorShift  = 12
	devArchMinorShift  = 16
	devArchVersionMask = 0xF
	idr1VersionMask    = 0xFF0
	idr1MajorShift     = 8
	idr1MinorShift     = 4
	configWFIWFEBit    = 1 << 17
)

// Config wraps the ETMv4 configuration with ETE-specific DEVARCH state.
type Config struct {
	etmv4.Config
	RegDevArch uint32
}

func NewConfig() *Config {
	return &Config{
		Config:     defaultETMv4Config(),
		RegDevArch: defaultDevArch,
	}
}

func defaultETMv4Config() etmv4.Config {
	return etmv4.Config{
		RegIdr0:    defaultIDR0,
		RegIdr1:    defaultIDR1,
		RegIdr2:    defaultIDR2,
		RegIdr8:    defaultIDR8,
		RegConfigr: defaultConfigR,
		ArchVer:    ocsd.ArchAA64,
		CoreProf:   ocsd.ProfileCortexA,
	}
}

func (c *Config) ToETMv4Config() *etmv4.Config {
	out := c.Config
	clearETMv4OnlyRegs(&out)
	applyDevArchVersion(&out, c.RegDevArch)

	// ETE always traces WFI/WFE. The ETMv4 base decoder relies on TRCCONFIGR bit 17.
	out.RegConfigr |= configWFIWFEBit
	out.ArchVer = ocsd.ArchAA64

	return &out
}

func clearETMv4OnlyRegs(cfg *etmv4.Config) {
	cfg.RegIdr9 = 0
	cfg.RegIdr10 = 0
	cfg.RegIdr11 = 0
	cfg.RegIdr12 = 0
	cfg.RegIdr13 = 0
}

func applyDevArchVersion(cfg *etmv4.Config, devArch uint32) {
	maj := (devArch >> devArchMajorShift) & devArchVersionMask
	min := (devArch >> devArchMinorShift) & devArchVersionMask
	cfg.RegIdr1 = (cfg.RegIdr1 &^ uint32(idr1VersionMask)) |
		(maj << idr1MajorShift) |
		(min << idr1MinorShift)
}
