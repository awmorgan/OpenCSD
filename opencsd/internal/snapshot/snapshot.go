package snapshot

import "errors"

// SnapshotConfig holds the parsed snapshot model.
type SnapshotConfig struct {
	Version  string
	Devices  []Device
	Trace    *TraceMetadata
	Clusters map[string][]string
}

// Device represents a core, trace source, or memory space.
type Device struct {
	Name      string
	Class     string
	Type      string
	Registers map[string][]RegisterValue
	Dumps     []MemoryDump
}

// RegisterValue captures a single register entry.
type RegisterValue struct {
	Value  string
	ID     string
	Size   string
	RawKey string
}

// MemoryDump represents a memory region.
type MemoryDump struct {
	FilePath string
	Address  uint64
	Length   *uint64
	Space    string
}

// TraceMetadata represents the trace.ini content.
type TraceMetadata struct {
	Buffers          map[string]TraceBuffer
	CoreTraceSources map[string]string
	SourceBuffers    map[string][]string
}

// TraceBuffer represents a trace buffer entry.
type TraceBuffer struct {
	Name   string
	Format string
	Files  []string
}

// LoadSnapshot parses a snapshot directory into a canonical model.
func LoadSnapshot(dirPath string) (*SnapshotConfig, error) {
	return nil, errors.New("LoadSnapshot not implemented")
}
