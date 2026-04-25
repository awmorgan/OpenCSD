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
	snapshotFound    bool
	readOK           bool
	ParsedDeviceList map[string]*ParsedDevice
	ParsedTrace      *ParsedTrace
	SourceTrees      map[string]*TraceBufferSourceTree
}

// NewReader creates a new Reader
func NewReader() *Reader {
	return &Reader{
		ParsedDeviceList: make(map[string]*ParsedDevice),
		SourceTrees:      make(map[string]*TraceBufferSourceTree),
	}
}

// SnapshotFound returns true if snapshot.ini was found
func (r *Reader) SnapshotFound() bool {
	return r.Found()
}

// Found returns true if snapshot.ini was found.
func (r *Reader) Found() bool {
	return r.snapshotFound
}

// SnapshotReadOK returns true if the parse was fully successful
func (r *Reader) SnapshotReadOK() bool {
	return r.ReadOK()
}

// ReadOK returns true if the parse was fully successful.
func (r *Reader) ReadOK() bool {
	return r.readOK
}

// Device returns the parsed device definition by name.
func (r *Reader) Device(name string) (*ParsedDevice, bool) {
	dev, ok := r.ParsedDeviceList[name]
	return dev, ok
}

// Trace returns parsed trace metadata.
func (r *Reader) Trace() *ParsedTrace {
	return r.ParsedTrace
}

// SourceTree returns a parsed source tree by buffer name.
func (r *Reader) SourceTree(name string) (*TraceBufferSourceTree, bool) {
	tree, ok := r.SourceTrees[name]
	return tree, ok
}

// Read reads the snapshot directory and parses all ini files.
func (r *Reader) Read() error {
	r.snapshotFound = false
	r.readOK = false
	r.ParsedDeviceList = make(map[string]*ParsedDevice)
	r.ParsedTrace = nil
	r.SourceTrees = make(map[string]*TraceBufferSourceTree)

	iniPath := filepath.Join(r.SnapshotPath, SnapshotINIFilename)
	file, err := os.Open(iniPath)
	if err != nil {
		return fmt.Errorf("open snapshot ini %s: %w", iniPath, err)
	}
	defer file.Close()

	r.snapshotFound = true

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
				r.ParsedTrace = parsedTrace

				// Extract source trees
				for _, bufInfo := range parsedTrace.TraceBuffers {
					tree := NewTraceBufferSourceTree()
					if ExtractSourceTree(bufInfo.BufferName, parsedTrace, tree) {
						r.SourceTrees[bufInfo.BufferName] = tree
					}
				}
			}
		}
	}

	r.readOK = true
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

	if parsedDev.DeviceName != "" {
		r.ParsedDeviceList[parsedDev.DeviceName] = parsedDev
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
