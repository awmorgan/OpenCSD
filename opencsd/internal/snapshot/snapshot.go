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
	entries, err := readSnapshotIni(snapshotPath, true)
	if err != nil {
		return nil, err
	}

	cfg := &SnapshotConfig{}
	var deviceFiles []string
	var traceMetadata string
	clusters := map[string][]string{}
	var snapshotVersion string
	var gotSnapshotVersion bool
	var gotSnapshotDescription bool
	var gotTraceMetadata bool

	for _, entry := range entries {
		switch entry.section {
		case "snapshot":
			switch entry.key {
			case "version":
				if gotSnapshotVersion {
					return nil, fmt.Errorf("duplicate snapshot version key")
				}
				gotSnapshotVersion = true
				snapshotVersion = entry.value
				cfg.Version = entry.value
			case "description":
				if gotSnapshotDescription {
					return nil, fmt.Errorf("duplicate snapshot description key")
				}
				gotSnapshotDescription = true
			}
		case "clusters":
			clusters[entry.key] = snapshotSplitCSV(entry.value)
		case "trace":
			if entry.key == "metadata" {
				if gotTraceMetadata {
					return nil, fmt.Errorf("duplicate trace metadata key")
				}
				gotTraceMetadata = true
				traceMetadata = entry.value
			}
		case "device_list":
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

func readSnapshotIni(path string, allowNoSection bool) ([]iniEntry, error) {
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
			if allowNoSection {
				continue
			}
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
	entries, err := readSnapshotIni(path, false)
	if err != nil {
		return nil, err
	}

	dev := &Device{Registers: map[string][]RegisterValue{}}
	dumpOrder := []string{}
	dumps := map[string]*MemoryDump{}
	dumpFields := map[string]*dumpFieldState{}
	regKeys := map[string]struct{}{}
	var gotDeviceName bool
	var gotDeviceClass bool
	var gotDeviceType bool
	var gotGlobalCore bool
	extendRegs := map[uint64]struct{}{}

	for _, entry := range entries {
		switch entry.section {
		case "device":
			switch entry.key {
			case "name":
				if gotDeviceName {
					return nil, fmt.Errorf("duplicate device name key")
				}
				gotDeviceName = true
				dev.Name = snapshotNoneToEmpty(entry.value)
			case "class":
				if gotDeviceClass {
					return nil, fmt.Errorf("duplicate device class key")
				}
				gotDeviceClass = true
				dev.Class = snapshotNoneToEmpty(entry.value)
			case "type":
				if gotDeviceType {
					return nil, fmt.Errorf("duplicate device type key")
				}
				gotDeviceType = true
				dev.Type = snapshotNoneToEmpty(entry.value)
			}
		case "global":
			if entry.key != "core" {
				return nil, fmt.Errorf("unknown global option %q", entry.key)
			}
			if gotGlobalCore {
				return nil, fmt.Errorf("duplicate global core key")
			}
			gotGlobalCore = true
		case "extendregs":
			key, err := snapshotParseUint64(entry.key)
			if err != nil {
				return nil, err
			}
			if _, exists := extendRegs[key]; exists {
				return nil, fmt.Errorf("duplicate extendregs key")
			}
			extendRegs[key] = struct{}{}
			if _, err := snapshotParseUint64(entry.value); err != nil {
				return nil, err
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
				if fields.gotFile {
					return nil, fmt.Errorf("duplicate dump file key")
				}
				dump.FilePath = snapshotTrimQuotes(entry.value)
				fields.gotFile = true
			case "space":
				if fields.gotSpace {
					return nil, fmt.Errorf("duplicate dump space key")
				}
				dump.Space = snapshotNoneToEmpty(snapshotTrimQuotes(entry.value))
				fields.gotSpace = true
			case "address":
				if fields.gotAddress {
					return nil, fmt.Errorf("duplicate dump address key")
				}
				addr, err := snapshotParseUint64(entry.value)
				if err != nil {
					return nil, err
				}
				dump.Address = addr
				fields.gotAddress = true
			case "length":
				if fields.gotLength {
					return nil, fmt.Errorf("duplicate dump length key")
				}
				length, err := snapshotParseOptionalUint64(entry.value)
				if err != nil {
					return nil, err
				}
				dump.Length = length
				fields.gotLength = true
			case "offset":
				if fields.gotOffset {
					return nil, fmt.Errorf("duplicate dump offset key")
				}
				offset, err := snapshotParseOptionalUint64(entry.value)
				if err != nil {
					return nil, err
				}
				dump.Offset = offset
				fields.gotOffset = true
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
	entries, err := readSnapshotIni(path, false)
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
	bufferKeys := map[string]map[string]bool{}
	bufferIDSet := map[string]struct{}{}
	var gotBufferList bool

	for _, entry := range entries {
		switch entry.section {
		case "trace_buffers":
			if entry.key == "buffers" {
				if gotBufferList {
					return nil, fmt.Errorf("duplicate trace buffer list key")
				}
				gotBufferList = true
				bufferIDs = snapshotSplitCSVRaw(entry.value)
				bufferIDSet = map[string]struct{}{}
				for _, id := range bufferIDs {
					bufferIDSet[id] = struct{}{}
				}
			}
		case "source_buffers":
			trace.SourceBuffers[entry.key] = []string{entry.value}
		case "core_trace_sources":
			trace.CoreTraceSources[entry.value] = entry.key
		default:
			if _, ok := bufferIDSet[entry.section]; !ok {
				continue
			}
			buf := bufferMeta[entry.section]
			if buf == nil {
				buf = &TraceBuffer{}
				bufferMeta[entry.section] = buf
			}
			keys := bufferKeys[entry.section]
			if keys == nil {
				keys = map[string]bool{}
				bufferKeys[entry.section] = keys
			}
			if keys[entry.key] {
				return nil, fmt.Errorf("duplicate trace buffer key")
			}
			keys[entry.key] = true
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

	for id, buf := range bufferMeta {
		if buf.Name == "" {
			return nil, fmt.Errorf("trace buffer section missing required buffer name")
		}
		if len(buf.Files) == 0 {
			return nil, fmt.Errorf("trace buffer section is missing mandatory file definition")
		}
		trace.Buffers[id] = *buf
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

	return strings.ToUpper(regName), id, size, rawKey
}

func normalizeRegValue(value string, size string) (string, error) {
	trimmed := strings.TrimSpace(snapshotTrimQuotes(value))
	if size != "<none>" {
		sizeBits, err := strconv.Atoi(size)
		if err != nil {
			return trimmed, nil
		}
		num, err := strconv.ParseUint(trimmed, 0, 64)
		if err != nil {
			return trimmed, nil
		}
		width := (sizeBits + 3) / 4
		return fmt.Sprintf("0x%0*x", width, num), nil
	}

	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		return "0x" + strings.ToLower(trimmed[2:]), nil
	}

	num, err := strconv.ParseUint(trimmed, 0, 64)
	if err != nil {
		return trimmed, nil
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
		return nil, fmt.Errorf("invalid uint64: %s", value)
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
	gotLength  bool
	gotOffset  bool
	gotSpace   bool
}

func snapshotTrimQuotes(value string) string {
	trimmed := strings.TrimSpace(value)
	return strings.Trim(trimmed, "\"'")
}

func snapshotSplitCSVRaw(value string) []string {
	items := strings.Split(value, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
