package snapshot

import (
	"io"
	"maps"
	"strconv"
	"strings"
)

// ParseSingleDevice parses a device ini file
func ParseSingleDevice(input io.Reader) (*Device, error) {
	ini := ParseIni(input)
	parsed := NewParsedDevice()

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

	// Extended regs section ([extendregs]) — numeric address → value pairs.
	if extSec, ok := ini.Sections[ExtendedRegsSectionName]; ok {
		for k, v := range extSec {
			addr, errA := strconv.ParseUint(strings.TrimSpace(k), 0, 32)
			val, errV := strconv.ParseUint(strings.TrimSpace(v), 0, 32)
			if errA == nil && errV == nil {
				parsed.ExtRegs[uint32(addr)] = uint32(val)
			}
		}
	}

	// Dump sections (prefix "dump") — iterate in file declaration order via SectionOrder.
	for _, secName := range ini.SectionOrder {
		if !strings.HasPrefix(strings.ToLower(secName), DumpFileSectionPrefix) {
			continue
		}
		secMap, ok := ini.Sections[secName]
		if !ok {
			continue
		}
		var dump MemoryDump

		if addrStr, ok := secMap[DumpAddressKey]; ok {
			dump.Address = parseUint(addrStr)
		}
		if lenStr, ok := secMap[DumpLengthKey]; ok {
			dump.Length = parseUint(lenStr)
		}
		if offStr, ok := secMap[DumpOffsetKey]; ok {
			dump.Offset = parseUint(offStr)
		}
		if file, ok := secMap[DumpFileKey]; ok {
			dump.Path = file
		}
		if space, ok := secMap[DumpSpaceKey]; ok {
			dump.Space = space
		}

		parsed.Memory = append(parsed.Memory, dump)
	}

	return parsed, nil
}

// ParseDeviceList parses the snapshot.ini file
func ParseDeviceList(input io.Reader) (*ParsedDevices, error) {
	ini := ParseIni(input)
	parsed := NewParsedDevices()

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
	ini := ParseIni(input)
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

// ExtractSourceTree builds a source tree for a single buffer
func ExtractSourceTree(bufferName string, metadata *Trace, bufferData *TraceBufferSourceTree) bool {
	// Find buffer info
	var foundInfo *Buffer
	for i := range metadata.TraceBuffers {
		if metadata.TraceBuffers[i].BufferName == bufferName {
			foundInfo = &metadata.TraceBuffers[i]
			break
		}
	}

	if foundInfo == nil {
		return false
	}

	bufferData.BufferInfo = foundInfo

	// Find sources associated with this buffer
	for sourceName, bName := range metadata.SourceBufferAssoc {
		if bName == bufferName {
			// associate core device with source device
			coreName := "<none>"
			if cName, ok := metadata.CPUSourceAssoc[sourceName]; ok {
				coreName = cName
			} else {
				// Search values instead of keys; values may be comma-separated when a core
				// has multiple sessions (duplicate keys accumulated by the INI parser).
				for k, v := range metadata.CPUSourceAssoc {
					for sv := range strings.SplitSeq(v, ",") {
						if strings.TrimSpace(sv) == sourceName {
							coreName = k
							break
						}
					}
					if coreName != "<none>" {
						break
					}
				}
			}
			bufferData.SourceCoreAssoc[sourceName] = coreName
		}
	}

	return true
}

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 0, 64)
	return v
}
