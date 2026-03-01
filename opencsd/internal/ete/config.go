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
)

type Config struct {
	etmv4.Config
	RegDevArch uint32
}

func NewConfig() *Config {
	return &Config{
		Config: etmv4.Config{
			RegIdr0:     defaultIDR0,
			RegIdr1:     defaultIDR1,
			RegIdr2:     defaultIDR2,
			RegIdr8:     defaultIDR8,
			RegIdr9:     0,
			RegIdr10:    0,
			RegIdr11:    0,
			RegIdr12:    0,
			RegIdr13:    0,
			RegConfigr:  defaultConfigR,
			RegTraceidr: 0,
			ArchVer:     ocsd.ArchAA64,
			CoreProf:    ocsd.ProfileCortexA,
		},
		RegDevArch: defaultDevArch,
	}
}

func (c *Config) ToETMv4Config() *etmv4.Config {
	out := c.Config

	out.RegIdr9 = 0
	out.RegIdr10 = 0
	out.RegIdr11 = 0
	out.RegIdr12 = 0
	out.RegIdr13 = 0

	if c.RegDevArch != 0 {
		maj := (c.RegDevArch >> 12) & 0xF
		min := (c.RegDevArch >> 16) & 0xF
		out.RegIdr1 = (out.RegIdr1 &^ uint32(0xFF0)) | (maj << 8) | (min << 4)
	}

	return &out
}
