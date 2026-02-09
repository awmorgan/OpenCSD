package snapshot

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

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
	Offset   *uint64
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
	snapshotPath := filepath.Join(dirPath, "snapshot.ini")
	entries, err := readSnapshotIni(snapshotPath)
	if err != nil {
		return nil, err
	}

	cfg := &SnapshotConfig{}
	var deviceFiles []string
	var traceMetadata string
	clusters := map[string][]string{}
	var snapshotVersion string

	for _, entry := range entries {
		switch entry.section {
		case "snapshot":
			if entry.key == "version" {
				snapshotVersion = entry.value
				cfg.Version = entry.value
			}
		case "clusters":
			clusters[entry.key] = snapshotSplitCSV(entry.value)
		case "trace":
			if entry.key == "metadata" {
				traceMetadata = entry.value
			}
		default:
			deviceFiles = append(deviceFiles, entry.value)
		}
	}

	if snapshotVersion != "" && snapshotVersion != "1" && snapshotVersion != "1.0" {
		return nil, fmt.Errorf("illegal snapshot file version: %s", snapshotVersion)
	}

	if len(clusters) > 0 {
		cfg.Clusters = clusters
	}

	for _, deviceFile := range deviceFiles {
		devicePath := filepath.Join(dirPath, deviceFile)
		dev, err := parseDeviceIni(devicePath)
		if err != nil {
			return nil, err
		}
		cfg.Devices = append(cfg.Devices, *dev)
	}

	if traceMetadata != "" {
		tracePath := filepath.Join(dirPath, traceMetadata)
		traceCfg, err := parseTraceIni(tracePath)
		if err != nil {
			return nil, err
		}
		cfg.Trace = traceCfg
	}

	return cfg, nil
}

type iniEntry struct {
	section string
	key     string
	value   string
}

func readSnapshotIni(path string) ([]iniEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []iniEntry
	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "\uFEFF") {
			line = strings.TrimPrefix(line, "\uFEFF")
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
		}
		if idx := strings.IndexAny(line, "\r;#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("invalid ini line in %s: %s", path, line)
		}
		key, value, ok := snapshotSplitKV(line)
		if !ok {
			return nil, fmt.Errorf("invalid ini line in %s: %s", path, line)
		}
		entries = append(entries, iniEntry{section: section, key: key, value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func snapshotSplitKV(line string) (string, string, bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func snapshotSplitCSV(value string) []string {
	items := strings.Split(value, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseDeviceIni(path string) (*Device, error) {
	entries, err := readSnapshotIni(path)
	if err != nil {
		return nil, err
	}

	dev := &Device{Registers: map[string][]RegisterValue{}}
	dumpOrder := []string{}
	dumps := map[string]*MemoryDump{}
	dumpFields := map[string]*dumpFieldState{}
	regKeys := map[string]struct{}{}

	for _, entry := range entries {
		switch entry.section {
		case "device":
			switch entry.key {
			case "name":
				dev.Name = snapshotNoneToEmpty(entry.value)
			case "class":
				dev.Class = snapshotNoneToEmpty(entry.value)
			case "type":
				dev.Type = snapshotNoneToEmpty(entry.value)
			}
		case "regs":
			regName, id, size, rawKey := parseRegKey(entry.key)
			regKey := strings.ToLower(rawKey)
			if _, exists := regKeys[regKey]; exists {
				return nil, fmt.Errorf("duplicate register key: %s", rawKey)
			}
			regKeys[regKey] = struct{}{}
			normValue, err := normalizeRegValue(snapshotTrimQuotes(entry.value), size)
			if err != nil {
				return nil, err
			}
			dev.Registers[regName] = append(dev.Registers[regName], RegisterValue{
				Value:  normValue,
				ID:     id,
				Size:   size,
				RawKey: rawKey,
			})
		default:
			if !strings.HasPrefix(entry.section, "dump") {
				continue
			}
			fields := dumpFields[entry.section]
			if fields == nil {
				fields = &dumpFieldState{}
				dumpFields[entry.section] = fields
			}
			dump := dumps[entry.section]
			if dump == nil {
				dump = &MemoryDump{}
				dumps[entry.section] = dump
				dumpOrder = append(dumpOrder, entry.section)
			}
			switch entry.key {
			case "file":
				dump.FilePath = snapshotTrimQuotes(entry.value)
				fields.gotFile = true
			case "space":
				dump.Space = snapshotNoneToEmpty(snapshotTrimQuotes(entry.value))
			case "address":
				addr, err := snapshotParseUint64(entry.value)
				if err != nil {
					return nil, err
				}
				dump.Address = addr
				fields.gotAddress = true
			case "length":
				length, err := snapshotParseOptionalUint64(entry.value)
				if err != nil {
					return nil, err
				}
				dump.Length = length
			case "offset":
				offset, err := snapshotParseOptionalUint64(entry.value)
				if err != nil {
					return nil, err
				}
				dump.Offset = offset
			default:
				return nil, fmt.Errorf("unknown dump key: %s", entry.key)
			}
		}
	}

	for _, section := range dumpOrder {
		fields := dumpFields[section]
		if fields == nil || !fields.gotAddress {
			return nil, fmt.Errorf("dump section missing mandatory address definition")
		}
		if !fields.gotFile {
			return nil, fmt.Errorf("dump section missing mandatory file definition")
		}
		if dump := dumps[section]; dump != nil {
			dev.Dumps = append(dev.Dumps, *dump)
		}
	}

	return dev, nil
}

func parseTraceIni(path string) (*TraceMetadata, error) {
	entries, err := readSnapshotIni(path)
	if err != nil {
		return nil, err
	}

	trace := &TraceMetadata{
		Buffers:          map[string]TraceBuffer{},
		CoreTraceSources: map[string]string{},
		SourceBuffers:    map[string][]string{},
	}

	bufferIDs := []string{}
	bufferMeta := map[string]*TraceBuffer{}

	for _, entry := range entries {
		switch entry.section {
		case "trace_buffers":
			if entry.key == "buffers" {
				bufferIDs = snapshotSplitCSV(entry.value)
			}
		case "source_buffers":
			value := strings.TrimSpace(entry.value)
			trace.SourceBuffers[entry.key] = []string{value}
		case "core_trace_sources":
			trace.CoreTraceSources[entry.value] = entry.key
		default:
			for _, id := range bufferIDs {
				if entry.section == id {
					buf := bufferMeta[id]
					if buf == nil {
						buf = &TraceBuffer{}
						bufferMeta[id] = buf
					}
					switch entry.key {
					case "name":
						buf.Name = entry.value
					case "format":
						buf.Format = snapshotNoneToEmpty(entry.value)
					case "file":
						buf.Files = snapshotSplitCSV(entry.value)
					}
				}
			}
		}
	}

	for _, id := range bufferIDs {
		if buf := bufferMeta[id]; buf != nil {
			if buf.Name == "" {
				return nil, fmt.Errorf("trace buffer section missing required buffer name")
			}
			if len(buf.Files) == 0 {
				return nil, fmt.Errorf("trace buffer section is missing mandatory file definition")
			}
			trace.Buffers[id] = *buf
		} else {
			return nil, fmt.Errorf("trace buffer section missing required buffer name")
		}
	}

	return trace, nil
}

func parseRegKey(key string) (string, string, string, string) {
	rawKey := strings.TrimSpace(key)
	regName := rawKey
	id := "<none>"
	size := "<none>"

	if openIdx := strings.Index(rawKey, "("); openIdx != -1 && strings.HasSuffix(rawKey, ")") {
		regName = strings.TrimSpace(rawKey[:openIdx])
		inner := strings.TrimSpace(rawKey[openIdx+1 : len(rawKey)-1])
		if after, ok := strings.CutPrefix(inner, "size:"); ok {
			size = strings.TrimSpace(after)
		} else if inner != "" {
			id = inner
		}
	}

	return regName, id, size, rawKey
}

func normalizeRegValue(value string, size string) (string, error) {
	trimmed := strings.TrimSpace(snapshotTrimQuotes(value))
	if size != "<none>" {
		sizeBits, err := strconv.Atoi(size)
		if err != nil {
			return "", fmt.Errorf("invalid size %q", size)
		}
		num, err := strconv.ParseUint(trimmed, 0, 64)
		if err != nil {
			return "", fmt.Errorf("invalid register value %q", value)
		}
		width := (sizeBits + 3) / 4
		return fmt.Sprintf("0x%0*x", width, num), nil
	}

	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		return "0x" + strings.ToLower(trimmed[2:]), nil
	}

	num, err := strconv.ParseUint(trimmed, 0, 64)
	if err != nil {
		return "", fmt.Errorf("invalid register value %q", value)
	}
	return fmt.Sprintf("0x%x", num), nil
}

func snapshotParseUint64(value string) (uint64, error) {
	v, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid uint64: %s", value)
	}
	return v, nil
}

func snapshotParseOptionalUint64(value string) (*uint64, error) {
	if value == "" || value == "<none>" {
		return nil, nil
	}
	v, err := snapshotParseUint64(value)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func snapshotNoneToEmpty(value string) string {
	if value == "<none>" {
		return ""
	}
	return value
}

type dumpFieldState struct {
	gotAddress bool
	gotFile    bool
}

func snapshotTrimQuotes(value string) string {
	trimmed := strings.TrimSpace(value)
	return strings.Trim(trimmed, "\"'")
}
