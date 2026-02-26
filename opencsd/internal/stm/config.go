package stm

type HWEventFeat int

const (
	HWEventUnknownDisabled HWEventFeat = iota
	HWEventEnabled
	HWEventUseRegisters
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
		RegTCSR:     0,
		RegDevID:    0xFF,    // default 256 masters
		RegFeat3R:   0x10000, // default 65536 channels
		RegFeat1R:   0x0,
		RegHWEvMast: 0,
		HWEvent:     HWEventUnknownDisabled,
		hwTraceEn:   false,
	}
}

func (c *Config) SetTraceID(traceID uint8) {
	IDmask := uint32(0x007F0000)
	c.RegTCSR &^= IDmask
	c.RegTCSR |= (uint32(traceID) << 16) & IDmask
}

func (c *Config) SetHWTraceFeat(hwFeat HWEventFeat) {
	c.HWEvent = hwFeat
	c.hwTraceEn = (c.HWEvent == HWEventEnabled)
	if c.HWEvent == HWEventUseRegisters {
		c.hwTraceEn = ((c.RegFeat1R & 0xC0000) == 0x80000) && ((c.RegTCSR & 0x8) == 0x8)
	}
}

func (c *Config) TraceID() uint8 {
	return uint8((c.RegTCSR >> 16) & 0x7F)
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
