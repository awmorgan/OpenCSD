package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestINIParser(t *testing.T) {
	iniData := `
; This is a comment
# Another comment
[snapshot]
version=1.0
description=Test Snapshot

[device_list]
cpu_0=cpu_0.ini
ETM_0=etm_0.ini

[trace]
metadata=trace.ini
`

	iniFile := ParseIni(strings.NewReader(iniData))

	if iniFile.GetSection("snapshot")["version"] != "1.0" {
		t.Errorf("expected version 1.0, got %s", iniFile.GetSection("snapshot")["version"])
	}
	if iniFile.GetSection("device_list")["cpu_0"] != "cpu_0.ini" {
		t.Errorf("expected cpu_0.ini")
	}
}

func TestParseDeviceList(t *testing.T) {
	iniData := `
[snapshot]
version=1.1
description=My Description
[device_list]
cpu_0=cpu_0.ini
[trace]
metadata=trace.ini
`
	devs, err := ParseDeviceList(strings.NewReader(iniData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if devs.SnapshotInfo.Version != "1.1" {
		t.Errorf("expected version 1.1")
	}
	if devs.DeviceList["cpu_0"] != "cpu_0.ini" {
		t.Errorf("expected cpu_0.ini")
	}
	if devs.TraceMetaDataName != "trace.ini" {
		t.Errorf("expected trace.ini")
	}
}

func TestParseSingleDevice(t *testing.T) {
	iniData := `
[global]
core=Cortex-A53
[device]
name=cpu_0
class=core
type=Cortex-A53
[regs]
TRCCONFIGR=0x00000001
[dump1]
file=memory.bin
address=0x80000000
length=0x1000
`
	dev, err := ParseSingleDevice(strings.NewReader(iniData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dev.FoundGlobal || dev.Core != "Cortex-A53" {
		t.Errorf("expected core Cortex-A53")
	}
	if dev.DeviceName != "cpu_0" {
		t.Errorf("expected name cpu_0")
	}
	val, ok := dev.GetRegValue("trcconfigr")
	if !ok || val != "0x00000001" {
		t.Errorf("expected TRCCONFIGR=0x00000001")
	}
	if len(dev.DumpDefs) != 1 {
		t.Fatalf("expected 1 dump def")
	}
	if dev.DumpDefs[0].Address != 0x80000000 {
		t.Errorf("expected address 0x80000000")
	}
	if dev.DumpDefs[0].Length != 0x1000 {
		t.Errorf("expected length 0x1000")
	}
	if dev.DumpDefs[0].Path != "memory.bin" {
		t.Errorf("expected file memory.bin")
	}
}

func TestParseTraceMetaData(t *testing.T) {
	iniData := `
[trace_buffers]
buffers=buffer1

[buffer1]
name=ETB_0
file=trace.bin
format=coresight

[source_buffers]
ETM_0=ETB_0

[core_trace_sources]
ETM_0=cpu_0
`
	trace, err := ParseTraceMetaData(strings.NewReader(iniData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(trace.BufferSectionNames) != 1 || trace.BufferSectionNames[0] != "buffer1" {
		t.Errorf("expected buffer1")
	}
	if len(trace.TraceBuffers) != 1 {
		t.Fatalf("expected 1 trace buffer")
	}
	if trace.TraceBuffers[0].BufferName != "ETB_0" {
		t.Errorf("expected ETB_0")
	}
	if trace.SourceBufferAssoc["ETM_0"] != "ETB_0" {
		t.Errorf("expected ETM_0 -> ETB_0")
	}
	if trace.CPUSourceAssoc["ETM_0"] != "cpu_0" {
		t.Errorf("expected ETM_0 -> cpu_0")
	}

	tree := NewTraceBufferSourceTree()
	ok := ExtractSourceTree("ETB_0", trace, tree)
	if !ok {
		t.Fatalf("expected to extract tree")
	}
	if tree.BufferInfo.DataFormat != "coresight" {
		t.Errorf("expected format coresight")
	}
	if tree.SourceCoreAssoc["ETM_0"] != "cpu_0" {
		t.Errorf("expected ETM_0 -> cpu_0 in tree")
	}

	// Test non-existent buffer
	ok = ExtractSourceTree("NON_EXISTENT", trace, tree)
	if ok {
		t.Errorf("expected false")
	}
}

func TestParseUint(t *testing.T) {
	if v := parseUint("0x10"); v != 16 {
		t.Errorf("expected 16, got %d", v)
	}
	if v := parseUint("16"); v != 16 {
		t.Errorf("expected 16, got %d", v)
	}
}

func TestExtractSourceTree_NoCore(t *testing.T) {
	trace := NewParsedTrace()
	trace.TraceBuffers = append(trace.TraceBuffers, TraceBufferInfo{BufferName: "buf1"})
	trace.SourceBufferAssoc["src1"] = "buf1"

	tree := NewTraceBufferSourceTree()
	ok := ExtractSourceTree("buf1", trace, tree)
	if !ok {
		t.Fatalf("expected to extract tree")
	}
	if tree.SourceCoreAssoc["src1"] != "<none>" {
		t.Errorf("expected <none> for source without core, got %s", tree.SourceCoreAssoc["src1"])
	}
}

func TestReader(t *testing.T) {
	// Create a temporary directory structure mimicking a snapshot
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "snapshot.ini"), []byte(`
[snapshot]
[device_list]
cpu_0=cpu_0.ini
[trace]
metadata=trace.ini
`), 0644)
	if err != nil {
		t.Fatalf("failed to create snapshot.ini: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "cpu_0.ini"), []byte(`
[device]
name=cpu_0
[dump1]
address=0x0
offset=0x1
space=memory
`), 0644)
	if err != nil {
		t.Fatalf("failed to create cpu_0.ini: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "trace.ini"), []byte(`
[trace_buffers]
buffers=buffer1
[buffer1]
name=ETB
file=trace.bin
[source_buffers]
ETM_0=ETB
[core_trace_sources]
ETM_0=cpu_0
`), 0644)
	if err != nil {
		t.Fatalf("failed to create trace.ini: %v", err)
	}

	reader := NewReader()
	reader.SetSnapshotDir(tempDir)
	reader.Verbose = true

	if ok := reader.ReadSnapShot(); !ok {
		t.Fatalf("expected success")
	}

	if !reader.SnapshotFound() {
		t.Errorf("expected snapshot found")
	}

	if !reader.SnapshotReadOK() {
		t.Errorf("expected read ok")
	}

	if r, ok := reader.ParsedDeviceList["cpu_0"]; !ok {
		t.Errorf("expected cpu_0")
	} else {
		if len(r.DumpDefs) != 1 {
			t.Errorf("expected 1 dump")
		} else {
			if r.DumpDefs[0].Offset != 1 {
				t.Errorf("expected offset 1")
			}
			if r.DumpDefs[0].Space != "memory" {
				t.Errorf("expected space memory")
			}
		}
	}

	if reader.ParsedTrace == nil {
		t.Fatalf("expected parsed trace")
	}

	if _, ok := reader.SourceTrees["ETB"]; !ok {
		t.Errorf("expected ETB source tree")
	}
}

func TestReader_Errors(t *testing.T) {
	reader := NewReader()
	reader.Verbose = true
	// Invalid path
	reader.SetSnapshotDir("/non/existent/path/for/sure")
	if ok := reader.ReadSnapShot(); ok {
		t.Errorf("expected failure")
	}

	tempDir := t.TempDir()
	reader.SetSnapshotDir(tempDir)

	// missing device file
	os.WriteFile(filepath.Join(tempDir, "snapshot.ini"), []byte(`
[device_list]
cpu_0=missing.ini
[trace]
metadata=missing_trace.ini
`), 0644)

	// should still return true as it read snapshot.ini but individual files failed
	if ok := reader.ReadSnapShot(); !ok {
		t.Errorf("expected success reading snapshot.ini even if sub files fail")
	}

	// Create bad trace.ini? No error returned from parseTraceMetaData typically,
	// but it would log if file missing. Which is covered above.

	reader.logInfo("test log info")
	reader.Verbose = false
	reader.logInfo("should not log")
}
