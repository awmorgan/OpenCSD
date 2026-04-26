package snapshot

import (
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"
)

// parseOptionalUint looks up key in sec and parses it as a uint64.
// If the key is absent it returns 0 with no error.
func parseOptionalUint(sec map[string]string, secName, key string) (uint64, error) {
	s, ok := sec[key]
	if !ok {
		return 0, nil
	}

	v, err := parseUint(s)
	if err != nil {
		return 0, fmt.Errorf("%s.%s: %w", secName, key, err)
	}
	return v, nil
}

// parseMemoryDump builds a MemoryDump from a parsed INI section map.
func parseMemoryDump(secName string, sec map[string]string) (MemoryDump, error) {
	addr, err := parseOptionalUint(sec, secName, DumpAddressKey)
	if err != nil {
		return MemoryDump{}, err
	}

	length, err := parseOptionalUint(sec, secName, DumpLengthKey)
	if err != nil {
		return MemoryDump{}, err
	}

	offset, err := parseOptionalUint(sec, secName, DumpOffsetKey)
	if err != nil {
		return MemoryDump{}, err
	}

	return MemoryDump{
		Address: addr,
		Length:  length,
		Offset:  offset,
		Path:    sec[DumpFileKey],
		Space:   sec[DumpSpaceKey],
	}, nil
}

// ParseSingleDevice parses a device ini file
func ParseSingleDevice(input io.Reader) (*Device, error) {
	ini, err := ParseIni(input)
	if err != nil {
		return nil, err
	}
	parsed := &Device{
		Memory:  []MemoryDump{},
		Regs:    make(map[string]string),
		ExtRegs: make(map[uint32]uint32),
	}

	// Global section (deprecated/unused in trace decode, but keep for completeness)
	if globalSec, ok := ini.Sections[GlobalSectionName]; ok {
		parsed.FoundGlobal = true
		if core, ok := globalSec[CoreKey]; ok {
			parsed.Core = core
		}
	}

	// Device section
	if deviceSec, ok := ini.Sections[DeviceSectionName]; ok {
		parsed.Name = deviceSec[DeviceNameKey]
		parsed.Class = deviceSec[DeviceClassKey]
		parsed.Type = deviceSec[DeviceTypeKey]
	}

	// Symbolic Regs section
	if regsSec, ok := ini.Sections[SymbolicRegsSectionName]; ok {
		for k, v := range regsSec {
			parsed.Regs[strings.ToLower(k)] = v
		}
	}

	// Extended regs section ([extendregs]) - numeric address → value pairs.
	if extSec, ok := ini.Sections[ExtendedRegsSectionName]; ok {
		for k, v := range extSec {
			addr, errA := strconv.ParseUint(strings.TrimSpace(k), 0, 32)
			val, errV := strconv.ParseUint(strings.TrimSpace(v), 0, 32)
			if errA == nil && errV == nil {
				parsed.ExtRegs[uint32(addr)] = uint32(val)
			}
		}
	}

	// Dump sections (prefix "dump") - iterate in file declaration order via SectionOrder.
	for _, secName := range ini.SectionOrder {
		if !strings.HasPrefix(strings.ToLower(secName), DumpFileSectionPrefix) {
			continue
		}

		dump, err := parseMemoryDump(secName, ini.Sections[secName])
		if err != nil {
			return nil, err
		}

		parsed.Memory = append(parsed.Memory, dump)
	}

	return parsed, nil
}

// ParseDeviceList parses the snapshot.ini file
func ParseDeviceList(input io.Reader) (*ParsedDevices, error) {
	ini, err := ParseIni(input)
	if err != nil {
		return nil, err
	}
	parsed := &ParsedDevices{
		DeviceList: make(map[string]string),
	}

	if snapSec, ok := ini.Sections[SnapshotSectionName]; ok {
		parsed.Version = snapSec[VersionKey]
		parsed.Description = snapSec[DescriptionKey]
	}

	if devListSec, ok := ini.Sections[DeviceListSectionName]; ok {
		maps.Copy(parsed.DeviceList, devListSec)
	}

	if parsed.Version == "" {
		if _, hasDeviceList := ini.Sections[DeviceListSectionName]; hasDeviceList {
			parsed.Version = "0.1"
		} else {
			parsed.Version = "0.0"
		}
	}

	if traceSec, ok := ini.Sections[TraceSectionName]; ok {
		parsed.TraceMetaDataName = traceSec[MetadataKey]
	}

	return parsed, nil
}

// ParseTraceMetaData parses the trace metadata ini file (trace.ini)
func ParseTraceMetaData(input io.Reader) (*Trace, error) {
	ini, err := ParseIni(input)
	if err != nil {
		return nil, err
	}
	parsed := &Trace{
		BufferSectionNames: []string{},
		TraceBuffers:       []Buffer{},
		SourceBufferAssoc:  make(map[string]string),
		CPUSourceAssoc:     make(map[string]string),
	}

	// trace_buffers section
	if tbSec, ok := ini.Sections[TraceBuffersSectionName]; ok {
		if buffers, ok := tbSec[BufferListKey]; ok {
			// Split by comma
			bufNames := strings.SplitSeq(buffers, ",")
			for bufName := range bufNames {
				name := strings.TrimSpace(bufName)
				if name != "" {
					parsed.BufferSectionNames = append(parsed.BufferSectionNames, name)
				}
			}
		}
	}

	// parse individual buffer sections
	for _, bufSecName := range parsed.BufferSectionNames {
		if bufSec, ok := ini.Sections[bufSecName]; ok {
			var info Buffer
			info.BufferName = bufSec[BufferNameKey]
			info.DataFileName = bufSec[BufferFileKey]
			info.DataFormat = bufSec[BufferFormatKey]
			parsed.TraceBuffers = append(parsed.TraceBuffers, info)
		}
	}

	// source_buffers section
	if sbSec, ok := ini.Sections[SourceBuffersSectionName]; ok {
		maps.Copy(parsed.SourceBufferAssoc, sbSec)
	}

	// core_trace_sources section
	// Each entry has format core_name=source_name. A core may appear multiple times with
	// different sources (e.g. multi-session ETE), resulting in comma-separated accumulated
	// values from the INI parser's duplicate-key handling.
	if ctsSec, ok := ini.Sections[CoreSourcesSectionName]; ok {
		maps.Copy(parsed.CPUSourceAssoc, ctsSec)
	}

	return parsed, nil
}

// SourceTree builds a source tree for a single buffer.
func SourceTree(bufferName string, metadata *Trace) (*TraceBufferSourceTree, bool) {
	if metadata == nil {
		return nil, false
	}

	var bufferInfo *Buffer
	for i := range metadata.TraceBuffers {
		if metadata.TraceBuffers[i].BufferName == bufferName {
			bufferInfo = &metadata.TraceBuffers[i]
			break
		}
	}
	if bufferInfo == nil {
		return nil, false
	}

	tree := &TraceBufferSourceTree{
		BufferInfo:      bufferInfo,
		SourceCoreAssoc: make(map[string]string),
	}

	for sourceName, bName := range metadata.SourceBufferAssoc {
		if bName != bufferName {
			continue
		}
		tree.SourceCoreAssoc[sourceName] = metadata.coreForSource(sourceName)
	}

	return tree, true
}

func (t *Trace) coreForSource(sourceName string) string {
	if coreName, ok := t.CPUSourceAssoc[sourceName]; ok {
		return coreName
	}

	for coreName, sources := range t.CPUSourceAssoc {
		for source := range strings.SplitSeq(sources, ",") {
			if strings.TrimSpace(source) == sourceName {
				return coreName
			}
		}
	}

	return "<none>"
}

func parseUint(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(s), 0, 64)
}
