package itm

const (
	traceIDMask        uint32 = 0x007F0000
	traceIDShift              = 16
	tcrSWOEnable       uint32 = 0x10
	tcrTSPrescaleShift        = 8
)

var tsPrescaleValues = [...]uint32{1, 4, 16, 64}

type HWEventFeat int

const (
	HWEventUnknownDisabled HWEventFeat = iota
	HWEventEnabled
	HWEventUseRegisters
)

// Config represents ITM hardware configuration data.
// Represents the programmed and hardware configured state of an ITM device.
type Config struct {
	RegTCR uint32 // Contains CoreSight trace ID, TS prescaler
}

// SetTraceID sets the CoreSight trace ID.
func (c *Config) SetTraceID(traceID uint8) {
	c.RegTCR &^= traceIDMask
	c.RegTCR |= (uint32(traceID) << traceIDShift) & traceIDMask
}

// TraceID gets the CoreSight trace ID.
func (c *Config) TraceID() uint8 {
	return uint8((c.RegTCR & traceIDMask) >> traceIDShift)
}

// TSPrescaleValue gets the prescaler for the local ts clock.
func (c *Config) TSPrescaleValue() uint32 {
	if c.RegTCR&tcrSWOEnable == 0 {
		return tsPrescaleValues[0]
	}
	idx := (c.RegTCR >> tcrTSPrescaleShift) & 0x3
	return tsPrescaleValues[idx]
}
