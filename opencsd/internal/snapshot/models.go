package snapshot

import "strings"

type Snapshot struct {
	Version     string
	Description string
	Devices     map[string]*Device
	Trace       *Trace
}

// Device stores the entire parsed device ini file
type Device struct {
	Name        string
	Class       string
	Type        string
	Regs        map[string]string // Key is lowercase for case-insensitive lookup
	ExtRegs     map[uint32]uint32
	Memory      []MemoryDump
	FoundGlobal bool
	Core        string
}

type MemoryDump struct {
	Address uint64
	Path    string
	Length  uint64
	Offset  uint64
	Space   string
}

// NewParsedDevice creates a new Device
func NewParsedDevice() *Device {
	return &Device{
		Memory:  []MemoryDump{},
		Regs:    make(map[string]string),
		ExtRegs: make(map[uint32]uint32),
	}
}

// RegValue is a helper to get register value case-insensitively
func (p *Device) RegValue(key string) (string, bool) {
	keyLower := strings.ToLower(key)
	if val, ok := p.Regs[keyLower]; ok {
		return val, true
	}
	prefix := keyLower + "("
	for k, v := range p.Regs {
		if strings.HasPrefix(k, prefix) {
			return v, true
		}
	}
	return "", false
}

// ParsedDevices stores the entire device list and snapshot info
type ParsedDevices struct {
	DeviceList        map[string]string
	Version           string
	Description       string
	TraceMetaDataName string
}

// NewParsedDevices creates a new ParsedDevices
func NewParsedDevices() *ParsedDevices {
	return &ParsedDevices{
		DeviceList: make(map[string]string),
	}
}

// Buffer stores basic info about the buffer
type Buffer struct {
	BufferName   string
	DataFileName string
	DataFormat   string
}

// Trace stores lists of buffers and associations as presented in the ini file.
type Trace struct {
	BufferSectionNames []string
	TraceBuffers       []Buffer
	SourceBufferAssoc  map[string]string // trace source name -> trace buffer name assoc
	CPUSourceAssoc     map[string]string // trace source name -> cpu_name assoc
}

// NewParsedTrace creates a new Trace
func NewParsedTrace() *Trace {
	return &Trace{
		BufferSectionNames: []string{},
		TraceBuffers:       []Buffer{},
		SourceBufferAssoc:  make(map[string]string),
		CPUSourceAssoc:     make(map[string]string),
	}
}

// TraceBufferSourceTree stores single buffer information containing just the assoc for the buffer
type TraceBufferSourceTree struct {
	BufferInfo      *Buffer
	SourceCoreAssoc map[string]string // list of source names attached to core device names (e.g. ETM_0:cpu_0)
}

// NewTraceBufferSourceTree creates a new TraceBufferSourceTree
func NewTraceBufferSourceTree() *TraceBufferSourceTree {
	return &TraceBufferSourceTree{
		SourceCoreAssoc: make(map[string]string),
	}
}
