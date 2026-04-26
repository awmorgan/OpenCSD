package snapshot

import (
	"errors"
	"fmt"
	"io/fs"
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
	Warnings         []error
}

func (r *Reader) warn(err error) {
	if err != nil {
		r.Warnings = append(r.Warnings, err)
	}
}

func (r *Reader) reset() {
	r.SnapshotFound = false
	r.ReadOK = false
	r.ParsedDeviceList = make(map[string]*Device)
	r.Trace = nil
	r.SourceTrees = make(map[string]*TraceBufferSourceTree)
	r.Warnings = nil
}

// NewReader creates a new Reader
func NewReader() *Reader {
	r := &Reader{}
	r.reset()
	return r
}

// Read loads as much of the snapshot as possible.
// It returns an error only if snapshot.ini cannot be opened or parsed.
// Optional or trace-only content failures are recorded in r.Warnings.
func (r *Reader) Read() error {
	r.reset()

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

	for devName, iniFileName := range devList.DeviceList {
		r.warn(r.loadDevice(devName, iniFileName))
	}

	if len(devList.DeviceList) == 0 {
		r.loadLegacyDevices()
	}

	r.warn(r.readTraceMetadata(devList.TraceMetaDataName))

	r.ReadOK = true
	return nil
}

func (r *Reader) loadDevice(devName string, iniFileName string) error {
	devIniPath := filepath.Join(r.SnapshotPath, iniFileName)
	devFile, err := os.Open(devIniPath)
	if err != nil {
		return fmt.Errorf("failed to open device ini %s: %w", devIniPath, err)
	}
	defer devFile.Close()

	parsedDev, err := ParseSingleDevice(devFile)
	if err != nil {
		return fmt.Errorf("failed to parse device %s: %w", devName, err)
	}

	targetName := devName
	if parsedDev.Name != "" {
		targetName = parsedDev.Name
	}
	r.ParsedDeviceList[targetName] = parsedDev
	return nil
}

func (r *Reader) loadLegacyDevices() {
	for i := 0; ; i++ {
		name := fmt.Sprintf("device_%d.ini", i)
		path := filepath.Join(r.SnapshotPath, name)

		if _, err := os.Stat(path); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				r.warn(fmt.Errorf("stat legacy device %s: %w", path, err))
			}
			return
		}

		r.warn(r.loadDevice(fmt.Sprintf("device_%d", i), name))
	}
}

func (r *Reader) readTraceMetadata(name string) error {
	if name == "" {
		name = TraceINIFilename
	}

	path := filepath.Join(r.SnapshotPath, name)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open trace metadata %s: %w", path, err)
	}
	defer file.Close()

	trace, err := ParseTraceMetaData(file)
	if err != nil {
		return fmt.Errorf("parse trace metadata %s: %w", path, err)
	}

	r.Trace = trace
	for _, buf := range trace.TraceBuffers {
		tree, ok := SourceTree(buf.BufferName, trace)
		if ok {
			r.SourceTrees[buf.BufferName] = tree
		}
	}

	return nil
}
