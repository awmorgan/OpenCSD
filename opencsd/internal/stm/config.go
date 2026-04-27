package stm

type HWEventFeat int

const (
	HWEventUnknownDisabled HWEventFeat = iota
	HWEventEnabled
	HWEventUseRegisters
)

const (
	stmTraceIDMask      = uint32(0x007F0000)
	stmTraceIDShift     = 16
	stmDefaultMasters   = 0xFF
	stmDefaultChannels  = 0x10000
	stmHWEventFeatMask  = 0xC0000
	stmHWEventFeatValue = 0x80000
	stmHWTraceEnableBit = 0x8
)

// Config represents STM hardware configuration data.
// Represents the programmed and hardware configured state of an STM device.
type Config struct {
	RegTCSR     uint32
	RegFeat3R   uint32
	RegDevID    uint32
	RegFeat1R   uint32
	RegHWEvMast uint32
	HWEvent     HWEventFeat

	hwTraceEn bool
}

// NewConfig returns a default configuration with 256 masters, 65536 channels.
func NewConfig() *Config {
	return &Config{
		RegDevID:  stmDefaultMasters,
		RegFeat3R: stmDefaultChannels,
		HWEvent:   HWEventUnknownDisabled,
	}
}

func (c *Config) SetTraceID(traceID uint8) {
	c.RegTCSR &^= stmTraceIDMask
	c.RegTCSR |= (uint32(traceID) << stmTraceIDShift) & stmTraceIDMask
}

func (c *Config) SetHWTraceFeat(hwFeat HWEventFeat) {
	c.HWEvent = hwFeat

	switch hwFeat {
	case HWEventEnabled:
		c.hwTraceEn = true
	case HWEventUseRegisters:
		c.hwTraceEn = c.hwTraceEnabledByRegisters()
	default:
		c.hwTraceEn = false
	}
}

func (c *Config) hwTraceEnabledByRegisters() bool {
	return (c.RegFeat1R&stmHWEventFeatMask) == stmHWEventFeatValue &&
		(c.RegTCSR&stmHWTraceEnableBit) == stmHWTraceEnableBit
}

func (c *Config) TraceID() uint8 {
	return uint8((c.RegTCSR & stmTraceIDMask) >> stmTraceIDShift)
}

func (c *Config) MaxMasterIdx() uint8 {
	return uint8(c.RegDevID & 0xFF)
}

func (c *Config) MaxChannelIdx() uint16 {
	return uint16(c.RegFeat3R - 1)
}

func (c *Config) HWTraceMasterIdx() uint16 {
	return uint16(c.RegHWEvMast & 0xFFFF)
}

func (c *Config) HWTraceEn() bool {
	return c.hwTraceEn
}
