package snapshot

import "strings"

// Info stores version and description from snapshot.ini
type Info struct {
	Version     string
	Description string
}

// DumpDef stores a parsed [dump] section
type DumpDef struct {
	Address uint64
	Path    string
	Length  uint64
	Offset  uint64
	Space   string
}

// ParsedDevice stores the entire parsed device ini file
type ParsedDevice struct {
	FoundGlobal    bool
	Core           string
	DumpDefs       []DumpDef
	RegDefs        map[string]string // Key is lowercase for case-insensitive lookup
	ExtendRegDefs  map[uint32]uint32
	DeviceName     string
	DeviceClass    string
	DeviceTypeName string
}

// NewParsedDevice creates a new ParsedDevice
func NewParsedDevice() *ParsedDevice {
	return &ParsedDevice{
		DumpDefs:      []DumpDef{},
		RegDefs:       make(map[string]string),
		ExtendRegDefs: make(map[uint32]uint32),
	}
}

// GetRegValue is a helper to get register value case-insensitively
func (p *ParsedDevice) GetRegValue(key string) (string, bool) {
	val, ok := p.RegDefs[strings.ToLower(key)]
	return val, ok
}

// ParsedDevices stores the entire device list and snapshot info
type ParsedDevices struct {
	DeviceList        map[string]string
	SnapshotInfo      Info
	TraceMetaDataName string
}

// NewParsedDevices creates a new ParsedDevices
func NewParsedDevices() *ParsedDevices {
	return &ParsedDevices{
		DeviceList: make(map[string]string),
	}
}

// TraceBufferInfo stores basic info about the buffer
type TraceBufferInfo struct {
	BufferName   string
	DataFileName string
	DataFormat   string
}

// ParsedTrace stores lists of buffers and associations as presented in the ini file.
type ParsedTrace struct {
	BufferSectionNames []string
	TraceBuffers       []TraceBufferInfo
	SourceBufferAssoc  map[string]string // trace source name -> trace buffer name assoc
	CPUSourceAssoc     map[string]string // trace source name -> cpu_name assoc
}

// NewParsedTrace creates a new ParsedTrace
func NewParsedTrace() *ParsedTrace {
	return &ParsedTrace{
		BufferSectionNames: []string{},
		TraceBuffers:       []TraceBufferInfo{},
		SourceBufferAssoc:  make(map[string]string),
		CPUSourceAssoc:     make(map[string]string),
	}
}

// TraceBufferSourceTree stores single buffer information containing just the assoc for the buffer
type TraceBufferSourceTree struct {
	BufferInfo      *TraceBufferInfo
	SourceCoreAssoc map[string]string // list of source names attached to core device names (e.g. ETM_0:cpu_0)
}

// NewTraceBufferSourceTree creates a new TraceBufferSourceTree
func NewTraceBufferSourceTree() *TraceBufferSourceTree {
	return &TraceBufferSourceTree{
		SourceCoreAssoc: make(map[string]string),
	}
}
