package snapshot

import "strings"

type ParsedDevices struct {
	Version           string
	Description       string
	DeviceList        map[string]string
	TraceMetaDataName string
}

type Device struct {
	Name        string
	Class       string
	Type        string
	Regs        map[string]string
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

func NewParsedDevice() *Device {
	return &Device{
		Memory:  []MemoryDump{},
		Regs:    make(map[string]string),
		ExtRegs: make(map[uint32]uint32),
	}
}

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

func NewParsedDevices() *ParsedDevices {
	return &ParsedDevices{
		DeviceList: make(map[string]string),
	}
}

type Buffer struct {
	BufferName   string
	DataFileName string
	DataFormat   string
}

type Trace struct {
	BufferSectionNames []string
	TraceBuffers       []Buffer
	SourceBufferAssoc  map[string]string
	CPUSourceAssoc     map[string]string
}

func NewParsedTrace() *Trace {
	return &Trace{
		BufferSectionNames: []string{},
		TraceBuffers:       []Buffer{},
		SourceBufferAssoc:  make(map[string]string),
		CPUSourceAssoc:     make(map[string]string),
	}
}

type TraceBufferSourceTree struct {
	BufferInfo      *Buffer
	SourceCoreAssoc map[string]string
}
