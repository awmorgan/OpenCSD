package snapshot

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type goldenCase struct {
	name        string
	snapshotDir string
	goldenFile  string
}

func TestLoadSnapshotGolden(t *testing.T) {
	testDir := testFileDir(t)
	repoRoot := filepath.Clean(filepath.Join(testDir, "..", "..", ".."))

	cases := []goldenCase{
		{
			name:        "bugfix-exact-match",
			snapshotDir: filepath.Join(repoRoot, "decoder", "tests", "snapshots", "bugfix-exact-match"),
			goldenFile:  filepath.Join(testDir, "testdata", "bugfix-exact-match.snapshot_parsed.txt"),
		},
		{
			name:        "juno_r1_1",
			snapshotDir: filepath.Join(repoRoot, "decoder", "tests", "snapshots", "juno_r1_1"),
			goldenFile:  filepath.Join(testDir, "testdata", "juno_r1_1.snapshot_parsed.txt"),
		},
		{
			name:        "test-file-mem-offsets",
			snapshotDir: filepath.Join(repoRoot, "decoder", "tests", "snapshots", "test-file-mem-offsets"),
			goldenFile:  filepath.Join(testDir, "testdata", "test-file-mem-offsets.snapshot_parsed.txt"),
		},
		{
			name:        "feat_cmpbr",
			snapshotDir: filepath.Join(repoRoot, "decoder", "tests", "snapshots-ete", "feat_cmpbr"),
			goldenFile:  filepath.Join(testDir, "testdata", "feat_cmpbr.snapshot_parsed.txt"),
		},
		{
			name:        "ts_marker",
			snapshotDir: filepath.Join(repoRoot, "decoder", "tests", "snapshots-ete", "ts_marker"),
			goldenFile:  filepath.Join(testDir, "testdata", "ts_marker.snapshot_parsed.txt"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := parseGoldenSnapshot(tc.goldenFile)
			if err != nil {
				t.Fatalf("parse golden failed: %v", err)
			}

			got, err := LoadSnapshot(tc.snapshotDir)
			if err != nil {
				t.Fatalf("LoadSnapshot(%s) error: %v", tc.snapshotDir, err)
			}

			normalizeSnapshot(expected)
			normalizeSnapshot(got)

			if !reflect.DeepEqual(expected, got) {
				t.Fatalf("snapshot mismatch for %s", tc.name)
			}
		})
	}
}

func testFileDir(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	return filepath.Dir(file)
}

func parseGoldenSnapshot(path string) (*SnapshotConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &SnapshotConfig{
		Clusters: map[string][]string{},
	}

	var (
		currentDevice     *Device
		currentDump       *MemoryDump
		currentTraceID    string
		currentTraceBuf   *TraceBuffer
		currentCore       string
		currentCoreSource string
		currentSrcName    string
		currentSrcBufs    []string
		section           string
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch line {
		case "[[device]]":
			flushDump(currentDevice, &currentDump)
			if currentDevice != nil {
				cfg.Devices = append(cfg.Devices, *currentDevice)
			}
			currentDevice = &Device{Registers: map[string][]RegisterValue{}}
			section = "device"
			continue
		case "[[dump]]":
			flushDump(currentDevice, &currentDump)
			currentDump = &MemoryDump{}
			section = "dump"
			continue
		case "[[trace_buffer]]":
			flushTraceBuffer(cfg, currentTraceID, &currentTraceBuf)
			currentTraceID = ""
			currentTraceBuf = &TraceBuffer{}
			section = "trace_buffer"
			continue
		case "[[core_trace_source]]":
			currentCore = ""
			currentCoreSource = ""
			section = "core_trace_source"
			continue
		case "[[source_buffer]]":
			currentSrcName = ""
			currentSrcBufs = nil
			section = "source_buffer"
			continue
		case "[[validation]]":
			section = "validation"
			continue
		}

		key, value, ok := splitKV(line)
		if !ok {
			return nil, fmt.Errorf("invalid line: %s", line)
		}

		switch {
		case key == "snapshot.version":
			cfg.Version = value
		case strings.HasPrefix(key, "cluster."):
			name := strings.TrimPrefix(key, "cluster.")
			cfg.Clusters[name] = splitCSV(value)
		case key == "trace.metadata":
			ensureTrace(cfg)
		case key == "trace_buffers.ids":
			ensureTrace(cfg)
		case strings.HasPrefix(key, "reg."):
			if currentDevice == nil {
				return nil, fmt.Errorf("reg outside device: %s", line)
			}
			regName := strings.TrimPrefix(key, "reg.")
			val, id, size, rawKey := parseRegValue(value)
			currentDevice.Registers[regName] = append(currentDevice.Registers[regName], RegisterValue{
				Value:  val,
				ID:     id,
				Size:   size,
				RawKey: rawKey,
			})
		case section == "device":
			if currentDevice == nil {
				return nil, fmt.Errorf("device fields without device section")
			}
			switch key {
			case "name":
				currentDevice.Name = value
			case "class":
				currentDevice.Class = noneToEmpty(value)
			case "type":
				currentDevice.Type = noneToEmpty(value)
			}
		case section == "dump":
			if currentDump == nil {
				return nil, fmt.Errorf("dump fields without dump section")
			}
			switch key {
			case "file":
				currentDump.FilePath = value
			case "space":
				currentDump.Space = noneToEmpty(value)
			case "address":
				addr, err := parseUint64(value)
				if err != nil {
					return nil, err
				}
				currentDump.Address = addr
			case "length":
				length, err := parseOptionalUint64(value)
				if err != nil {
					return nil, err
				}
				currentDump.Length = length
			}
		case section == "trace_buffer":
			ensureTrace(cfg)
			if currentTraceBuf == nil {
				return nil, fmt.Errorf("trace_buffer fields without trace_buffer section")
			}
			switch key {
			case "id":
				currentTraceID = value
			case "name":
				currentTraceBuf.Name = value
			case "format":
				currentTraceBuf.Format = noneToEmpty(value)
			case "files":
				currentTraceBuf.Files = splitCSV(value)
			}
		case section == "core_trace_source":
			ensureTrace(cfg)
			switch key {
			case "core":
				currentCore = value
			case "source":
				currentCoreSource = value
			}
			if currentCore != "" && currentCoreSource != "" {
				cfg.Trace.CoreTraceSources[currentCore] = currentCoreSource
			}
		case section == "source_buffer":
			ensureTrace(cfg)
			switch key {
			case "source":
				currentSrcName = value
			case "buffers":
				currentSrcBufs = splitCSV(value)
			}
			if currentSrcName != "" && currentSrcBufs != nil {
				cfg.Trace.SourceBuffers[currentSrcName] = currentSrcBufs
			}
		}
	}

	flushDump(currentDevice, &currentDump)
	if currentDevice != nil {
		cfg.Devices = append(cfg.Devices, *currentDevice)
	}
	flushTraceBuffer(cfg, currentTraceID, &currentTraceBuf)

	if len(cfg.Clusters) == 0 {
		cfg.Clusters = nil
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func ensureTrace(cfg *SnapshotConfig) {
	if cfg.Trace == nil {
		cfg.Trace = &TraceMetadata{
			Buffers:          map[string]TraceBuffer{},
			CoreTraceSources: map[string]string{},
			SourceBuffers:    map[string][]string{},
		}
	}
}

func flushDump(dev *Device, dump **MemoryDump) {
	if dev == nil || dump == nil || *dump == nil {
		return
	}
	dev.Dumps = append(dev.Dumps, **dump)
	*dump = nil
}

func flushTraceBuffer(cfg *SnapshotConfig, id string, buf **TraceBuffer) {
	if cfg.Trace == nil || buf == nil || *buf == nil {
		return
	}
	if id == "" {
		*buf = nil
		return
	}
	cfg.Trace.Buffers[id] = **buf
	*buf = nil
}

func splitKV(line string) (string, string, bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func splitCSV(value string) []string {
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

func noneToEmpty(value string) string {
	if value == "<none>" {
		return ""
	}
	return value
}

func parseUint64(value string) (uint64, error) {
	v, err := strconv.ParseUint(value, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid uint64: %s", value)
	}
	return v, nil
}

func parseOptionalUint64(value string) (*uint64, error) {
	if value == "<none>" {
		return nil, nil
	}
	v, err := parseUint64(value)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func parseRegValue(value string) (string, string, string, string) {
	parts := strings.SplitN(value, " ; ", 2)
	regValue := strings.TrimSpace(parts[0])
	id := "<none>"
	size := "<none>"
	rawKey := ""
	if len(parts) < 2 {
		return regValue, id, size, rawKey
	}
	meta := parts[1]
	if v, ok := extractToken(meta, "id="); ok {
		id = v
	}
	if v, ok := extractToken(meta, "size="); ok {
		size = v
	}
	if v, ok := extractQuoted(meta, "raw_key="); ok {
		rawKey = v
	}
	return regValue, id, size, rawKey
}

func extractToken(s, prefix string) (string, bool) {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return "", false
	}
	start := idx + len(prefix)
	end := strings.IndexAny(s[start:], " \t")
	if end == -1 {
		return s[start:], true
	}
	return s[start : start+end], true
}

func extractQuoted(s, prefix string) (string, bool) {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return "", false
	}
	start := idx + len(prefix)
	if start >= len(s) || s[start] != '"' {
		return "", false
	}
	start++
	end := strings.IndexByte(s[start:], '"')
	if end == -1 {
		return "", false
	}
	return s[start : start+end], true
}

func normalizeSnapshot(cfg *SnapshotConfig) {
	if cfg == nil {
		return
	}
	sort.Slice(cfg.Devices, func(i, j int) bool {
		return cfg.Devices[i].Name < cfg.Devices[j].Name
	})
	for i := range cfg.Devices {
		dev := &cfg.Devices[i]
		sort.Slice(dev.Dumps, func(a, b int) bool {
			if dev.Dumps[a].FilePath != dev.Dumps[b].FilePath {
				return dev.Dumps[a].FilePath < dev.Dumps[b].FilePath
			}
			return dev.Dumps[a].Address < dev.Dumps[b].Address
		})
		for key, regs := range dev.Registers {
			sort.Slice(regs, func(a, b int) bool {
				if regs[a].ID != regs[b].ID {
					return regs[a].ID < regs[b].ID
				}
				if regs[a].Value != regs[b].Value {
					return regs[a].Value < regs[b].Value
				}
				return regs[a].RawKey < regs[b].RawKey
			})
			dev.Registers[key] = regs
		}
	}
}
