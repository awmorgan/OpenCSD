package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
)

const SnapshotINIFilename = "snapshot.ini"

// Reader reads a snapshot directory
type Reader struct {
	SnapshotPath     string
	Verbose          bool
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

// SetSnapshotDir sets the directory to read from
func (r *Reader) SetSnapshotDir(dir string) {
	r.SnapshotPath = dir
}

// SnapshotFound returns true if snapshot.ini was found
func (r *Reader) SnapshotFound() bool {
	return r.snapshotFound
}

// SnapshotReadOK returns true if the parse was fully successful
func (r *Reader) SnapshotReadOK() bool {
	return r.readOK
}

// ReadSnapShot reads the snapshot directory and parses all ini files
func (r *Reader) ReadSnapShot() bool {
	r.snapshotFound = false
	r.readOK = false

	iniPath := filepath.Join(r.SnapshotPath, SnapshotINIFilename)
	file, err := os.Open(iniPath)
	if err != nil {
		r.logError(fmt.Sprintf("Failed to open %s: %v", iniPath, err))
		return false
	}
	defer file.Close()

	r.snapshotFound = true

	devList, err := ParseDeviceList(file)
	if err != nil {
		r.logError(fmt.Sprintf("Failed to parse device list from %s: %v", iniPath, err))
		return false
	}

	// Parse devices
	for devName, iniFileName := range devList.DeviceList {
		devIniPath := filepath.Join(r.SnapshotPath, iniFileName)
		devFile, err := os.Open(devIniPath)
		if err != nil {
			r.logError(fmt.Sprintf("Failed to open device ini %s: %v", devIniPath, err))
			continue
		}

		parsedDev, err := ParseSingleDevice(devFile)
		devFile.Close()
		if err != nil {
			r.logError(fmt.Sprintf("Failed to parse device %s: %v", devName, err))
			continue
		}

		r.ParsedDeviceList[devName] = parsedDev
	}

	// Parse trace metadata
	if devList.TraceMetaDataName != "" {
		traceIniPath := filepath.Join(r.SnapshotPath, devList.TraceMetaDataName)
		traceFile, err := os.Open(traceIniPath)
		if err != nil {
			r.logError(fmt.Sprintf("Failed to open trace metadata %s: %v", traceIniPath, err))
		} else {
			parsedTrace, err := ParseTraceMetaData(traceFile)
			traceFile.Close()
			if err != nil {
				r.logError(fmt.Sprintf("Failed to parse trace metadata %s: %v", traceIniPath, err))
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
	return true
}

func (r *Reader) logError(msg string) {
	if r.Verbose {
		fmt.Fprintln(os.Stderr, msg)
	}
}

func (r *Reader) logInfo(msg string) {
	if r.Verbose {
		fmt.Println(msg)
	}
}
