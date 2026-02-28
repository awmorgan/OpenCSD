package etmv4

import "opencsd/internal/ocsd"

type CondType int

const (
	CondPassFail CondType = iota
	CondHasAspr
)

type QSuppType int

const (
	QNone QSuppType = iota
	QCountOnly
	QNoCountOnly
	QFull
)

type LSP0Type int

const (
	LSP0None LSP0Type = iota
	LSP0L
	LSP0S
	LSP0LS
)

type CondITraceType int

const (
	CondTrDis  CondITraceType = 0
	CondTrLd   CondITraceType = 1
	CondTrSt   CondITraceType = 2
	CondTrLdSt CondITraceType = 3
	CondTrAll  CondITraceType = 7
)

type Config struct {
	RegIdr0     uint32
	RegIdr1     uint32
	RegIdr2     uint32
	RegIdr8     uint32
	RegIdr9     uint32
	RegIdr10    uint32
	RegIdr11    uint32
	RegIdr12    uint32
	RegIdr13    uint32
	RegConfigr  uint32
	RegTraceidr uint32
	ArchVer     ocsd.ArchVersion
	CoreProf    ocsd.CoreProfile
}

func (c *Config) LSasInstP0() bool {
	return (c.RegIdr0 & 0x6) == 0x6
}

func (c *Config) HasDataTrace() bool {
	return (c.RegIdr0 & 0x18) == 0x18
}

func (c *Config) HasBranchBroadcast() bool {
	return (c.RegIdr0 & 0x20) == 0x20
}

func (c *Config) HasCondTrace() bool {
	return (c.RegIdr0 & 0x40) == 0x40
}

func (c *Config) HasCycleCountI() bool {
	return (c.RegIdr0 & 0x80) == 0x80
}

func (c *Config) HasRetStack() bool {
	return (c.RegIdr0 & 0x200) == 0x200
}

func (c *Config) NumEvents() uint8 {
	return uint8(((c.RegIdr0 >> 10) & 0x3) + 1)
}

func (c *Config) HasCondType() CondType {
	if (c.RegIdr0 & 0x3000) == 0x1000 {
		return CondHasAspr
	}
	return CondPassFail
}

func (c *Config) QSuppType() QSuppType {
	return QSuppType((c.RegIdr0 >> 15) & 0x3)
}

func (c *Config) HasQElem() bool {
	return c.QSuppType() != QNone
}

func (c *Config) HasQFilter() bool {
	return (c.RegIdr0&0x4000) == 0x4000 && c.QSuppType() != QNone
}

func (c *Config) HasTrcExcpData() bool {
	return (c.RegIdr0 & 0x20000) == 0x20000
}

func (c *Config) EteHasTSMarker() bool {
	return c.FullVersion() >= 0x51 && (c.RegIdr0&0x800000) == 0x800000
}

func (c *Config) TimeStampSize() uint32 {
	tsSizeF := (c.RegIdr0 >> 24) & 0x1F
	if tsSizeF == 0x6 {
		return 48
	}
	if tsSizeF == 0x8 {
		return 64
	}
	return 0
}

func (c *Config) CommitOpt1() bool {
	return (c.RegIdr0&0x20000000) == 0x20000000 && c.HasCycleCountI()
}

func (c *Config) CommTransP0() bool {
	return (c.RegIdr0 & 0x40000000) == 0x0
}

func (c *Config) MajVersion() uint8 {
	return uint8((c.RegIdr1 >> 8) & 0xF)
}

func (c *Config) MinVersion() uint8 {
	return uint8((c.RegIdr1 >> 4) & 0xF)
}

func (c *Config) FullVersion() uint8 {
	return (c.MajVersion() << 4) | c.MinVersion()
}

func (c *Config) IaSizeMax() uint32 {
	if (c.RegIdr2 & 0x1F) == 0x8 {
		return 64
	}
	return 32
}

func (c *Config) CidSize() uint32 {
	if ((c.RegIdr2 >> 5) & 0x1F) == 0x4 {
		return 32
	}
	return 0
}

func (c *Config) VmidSize() uint32 {
	vmidszF := (c.RegIdr2 >> 10) & 0x1F
	if vmidszF == 1 {
		return 8
	} else if c.FullVersion() > 0x40 {
		if vmidszF == 2 {
			return 16
		} else if vmidszF == 4 {
			return 32
		}
	}
	return 0
}

func (c *Config) DaSize() uint32 {
	daSizeF := (c.RegIdr2 >> 15) & 0x1F
	if daSizeF > 0 {
		if daSizeF == 0x8 {
			return 64
		}
		return 32
	}
	return 0
}

func (c *Config) DvSize() uint32 {
	dvSizeF := (c.RegIdr2 >> 20) & 0x1F
	if dvSizeF > 0 {
		if dvSizeF == 0x8 {
			return 64
		}
		return 32
	}
	return 0
}

func (c *Config) CcSize() uint32 {
	return ((c.RegIdr2 >> 25) & 0xF) + 12
}

func (c *Config) VmidOpt() bool {
	return (c.RegIdr2&0x20000000) == 0x20000000 && c.MinVersion() > 0
}

func (c *Config) WfiwfeBranch() bool {
	return (c.RegIdr2&0x80000000) != 0 && c.FullVersion() >= 0x43
}

func (c *Config) MaxSpecDepth() uint32 {
	return c.RegIdr8
}

func (c *Config) P0_Key_Max() uint32 {
	if c.RegIdr9 == 0 {
		return 1
	}
	return c.RegIdr9
}

func (c *Config) P1_Key_Max() uint32 {
	return c.RegIdr10
}

func (c *Config) P1_Spcl_Key_Max() uint32 {
	return c.RegIdr11
}

func (c *Config) CondKeyMax() uint32 {
	return c.RegIdr12
}

func (c *Config) CondSpecKeyMax() uint32 {
	return c.RegIdr13
}

func (c *Config) CondKeyMaxIncr() uint32 {
	return c.RegIdr12 - c.RegIdr13
}

func (c *Config) TraceID() uint8 {
	return uint8(c.RegTraceidr & 0x7F)
}

func (c *Config) EnabledLSP0Trace() bool {
	return (c.RegConfigr & 0x6) != 0
}

func (c *Config) EnabledDVTrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && (c.RegConfigr&(1<<17)) != 0
}

func (c *Config) EnabledDATrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && (c.RegConfigr&(1<<16)) != 0
}

func (c *Config) EnabledDataTrace() bool {
	return c.EnabledDATrace() || c.EnabledDVTrace()
}

func (c *Config) LSP0Type() LSP0Type {
	return LSP0Type((c.RegConfigr & 0x6) >> 1)
}

func (c *Config) EnabledBrBroad() bool {
	return (c.RegConfigr & (1 << 3)) != 0
}

func (c *Config) EnabledCCI() bool {
	return (c.RegConfigr & (1 << 4)) != 0
}

func (c *Config) EnabledCID() bool {
	return (c.RegConfigr & (1 << 6)) != 0
}

func (c *Config) EnabledVMID() bool {
	return (c.RegConfigr & (1 << 7)) != 0
}

func (c *Config) EnabledVMIDOpt() bool {
	vmidOptVal := (c.RegConfigr & (1 << 15)) != 0
	if !c.VmidOpt() {
		vmidOptVal = false
		if c.FullVersion() >= 0x45 {
			vmidOptVal = (c.RegIdr2 & (1 << 30)) != 0
		}
	}
	return vmidOptVal
}

func (c *Config) EnabledCondITrace() CondITraceType {
	switch (c.RegConfigr >> 8) & 0x7 {
	case 1:
		return CondTrLd
	case 2:
		return CondTrSt
	case 3:
		return CondTrLdSt
	case 7:
		return CondTrAll
	default:
		return CondTrDis
	}
}

func (c *Config) EnabledTS() bool {
	return (c.RegConfigr & (1 << 11)) != 0
}

func (c *Config) EnabledRetStack() bool {
	return (c.RegConfigr & (1 << 12)) != 0
}

func (c *Config) EnabledQE() bool {
	return (c.RegConfigr & (3 << 13)) != 0
}
