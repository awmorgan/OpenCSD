package snapshot

import (
	"io"
	"maps"
	"strconv"
	"strings"
)

// ParseSingleDevice parses a device ini file
func ParseSingleDevice(input io.Reader) (*ParsedDevice, error) {
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
		parsed.DeviceName = deviceSec[DeviceNameKey]
		parsed.DeviceClass = deviceSec[DeviceClassKey]
		parsed.DeviceTypeName = deviceSec[DeviceTypeKey]
	}

	// Symbolic Regs section
	if regsSec, ok := ini.Sections[SymbolicRegsSectionName]; ok {
		for k, v := range regsSec {
			parsed.RegDefs[strings.ToLower(k)] = v
		}
	}

	// Dump sections (prefix "dump")
	for secName, secMap := range ini.Sections {
		if strings.HasPrefix(secName, DumpFileSectionPrefix) {
			var dump DumpDef

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

			parsed.DumpDefs = append(parsed.DumpDefs, dump)
		}
	}

	return parsed, nil
}

// ParseDeviceList parses the snapshot.ini file
func ParseDeviceList(input io.Reader) (*ParsedDevices, error) {
	ini := ParseIni(input)
	parsed := NewParsedDevices()

	if snapSec, ok := ini.Sections[SnapshotSectionName]; ok {
		parsed.SnapshotInfo.Version = snapSec[VersionKey]
		parsed.SnapshotInfo.Description = snapSec[DescriptionKey]
	}

	if devListSec, ok := ini.Sections[DeviceListSectionName]; ok {
		maps.Copy(parsed.DeviceList, devListSec)
	}

	if traceSec, ok := ini.Sections[TraceSectionName]; ok {
		parsed.TraceMetaDataName = traceSec[MetadataKey]
	}

	return parsed, nil
}

// ParseTraceMetaData parses the trace metadata ini file (trace.ini)
func ParseTraceMetaData(input io.Reader) (*ParsedTrace, error) {
	ini := ParseIni(input)
	parsed := NewParsedTrace()

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
			var info TraceBufferInfo
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
	if ctsSec, ok := ini.Sections[CoreSourcesSectionName]; ok {
		maps.Copy(parsed.CPUSourceAssoc, ctsSec)
	}

	return parsed, nil
}

// ExtractSourceTree builds a source tree for a single buffer
func ExtractSourceTree(bufferName string, metadata *ParsedTrace, bufferData *TraceBufferSourceTree) bool {
	// Find buffer info
	var foundInfo *TraceBufferInfo
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
				// Search values instead of keys
				for k, v := range metadata.CPUSourceAssoc {
					if v == sourceName {
						coreName = k
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
	// Handle 0x prefix manually if base is 0, ParseUint handles it but expects to be cleanly formatted
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, _ := strconv.ParseUint(s[2:], 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}
