package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
)

const SnapshotINIFilename = "snapshot.ini"
const TraceINIFilename = "trace.ini"

// Reader reads a snapshot directory
type Reader struct {
	SnapshotPath     string
	SnapshotFound    bool
	ReadOK           bool
	ParsedDeviceList map[string]*Device
	Trace            *Trace
	SourceTrees      map[string]*TraceBufferSourceTree
}

// NewReader creates a new Reader
func NewReader() *Reader {
	return &Reader{
		ParsedDeviceList: make(map[string]*Device),
		SourceTrees:      make(map[string]*TraceBufferSourceTree),
	}
}

// Read reads the snapshot directory and parses all ini files.
func (r *Reader) Read() error {
	r.SnapshotFound = false
	r.ReadOK = false
	r.ParsedDeviceList = make(map[string]*Device)
	r.Trace = nil
	r.SourceTrees = make(map[string]*TraceBufferSourceTree)

	iniPath := filepath.Join(r.SnapshotPath, SnapshotINIFilename)
	file, err := os.Open(iniPath)
	if err != nil {
		return fmt.Errorf("open snapshot ini %s: %w", iniPath, err)
	}
	defer file.Close()

	r.SnapshotFound = true

	devList, err := ParseDeviceList(file)
	if err != nil {
		return fmt.Errorf("parse device list %s: %w", iniPath, err)
	}

	// Parse devices
	for devName, iniFileName := range devList.DeviceList {
		r.loadDevice(devName, iniFileName)
	}

	if len(devList.DeviceList) == 0 {
		r.loadLegacyDevices()
	}

	// Parse trace metadata
	traceMetaName := devList.TraceMetaDataName
	if traceMetaName == "" {
		traceMetaName = TraceINIFilename
	}

	if traceMetaName != "" {
		traceIniPath := filepath.Join(r.SnapshotPath, traceMetaName)
		traceFile, err := os.Open(traceIniPath)
		if err != nil {
		} else {
			parsedTrace, err := ParseTraceMetaData(traceFile)
			traceFile.Close()
			if err != nil {
			} else {
				r.Trace = parsedTrace

				// Extract source trees
				for _, bufInfo := range parsedTrace.TraceBuffers {
					tree := &TraceBufferSourceTree{
						SourceCoreAssoc: make(map[string]string),
					}
					if ExtractSourceTree(bufInfo.BufferName, parsedTrace, tree) {
						r.SourceTrees[bufInfo.BufferName] = tree
					}
				}
			}
		}
	}

	r.ReadOK = true
	return nil
}

func (r *Reader) loadDevice(devName string, iniFileName string) {
	devIniPath := filepath.Join(r.SnapshotPath, iniFileName)
	devFile, err := os.Open(devIniPath)
	if err != nil {
		return
	}

	parsedDev, err := ParseSingleDevice(devFile)
	devFile.Close()
	if err != nil {
		return
	}

	if parsedDev.Name != "" {
		r.ParsedDeviceList[parsedDev.Name] = parsedDev
		return
	}

	r.ParsedDeviceList[devName] = parsedDev
}

func (r *Reader) loadLegacyDevices() {
	for deviceIdx := 0; ; deviceIdx++ {
		legacyIniFileName := fmt.Sprintf("device_%d.ini", deviceIdx)
		legacyIniPath := filepath.Join(r.SnapshotPath, legacyIniFileName)
		if _, err := os.Stat(legacyIniPath); err != nil {
			break
		}
		r.loadDevice(fmt.Sprintf("device_%d", deviceIdx), legacyIniFileName)
	}
}
