package itm

// Config represents ITM hardware configuration data.
// Represents the programmed and hardware configured state of an ITM device.
type Config struct {
	RegTCR uint32 // Contains CoreSight trace ID, TS prescaler
}

// NewConfig creates a default configuration
func NewConfig() *Config {
	return &Config{}
}

// SetTraceID sets the CoreSight trace ID.
func (c *Config) SetTraceID(traceID uint8) {
	IDmask := uint32(0x007F0000)
	c.RegTCR &= ^IDmask
	c.RegTCR |= (uint32(traceID) << 16) & IDmask
}

// TraceID gets the CoreSight trace ID.
func (c *Config) TraceID() uint8 {
	return uint8((c.RegTCR >> 16) & 0x7F)
}

// TSPrescaleValue gets the prescaler for the local ts clock.
func (c *Config) TSPrescaleValue() uint32 {
	prescaleVals := []uint32{1, 4, 16, 64}
	preScaleIdx := 0

	// prescaler is used with TPIU clock - SWOENA = 1b1 - bit[4]
	if (c.RegTCR & 0x10) != 0 {
		preScaleIdx = int((c.RegTCR >> 8) & 0x3)
	}
	return prescaleVals[preScaleIdx]
}
