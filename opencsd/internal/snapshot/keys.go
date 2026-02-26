package snapshot

const (
	// snapshot.ini keys
	SnapshotSectionName = "snapshot"
	VersionKey          = "version"
	DescriptionKey      = "description"

	DeviceListSectionName = "device_list"

	TraceSectionName = "trace"
	MetadataKey      = "metadata"

	// device .ini keys (device_N.ini or cpu_N.ini)
	DeviceSectionName = "device"
	DeviceNameKey     = "name"
	DeviceClassKey    = "class"
	DeviceTypeKey     = "type"

	SymbolicRegsSectionName = "regs"

	DumpFileSectionPrefix = "dump"
	DumpAddressKey        = "address"
	DumpLengthKey         = "length"
	DumpOffsetKey         = "offset"
	DumpFileKey           = "file"
	DumpSpaceKey          = "space"

	// trace.ini keys
	TraceBuffersSectionName = "trace_buffers"
	BufferListKey           = "buffers"

	BufferSectionPrefix = "buffer"
	BufferNameKey       = "name"
	BufferFileKey       = "file"
	BufferFormatKey     = "format"

	SourceBuffersSectionName = "source_buffers"
	CoreSourcesSectionName   = "core_trace_sources"

	// deprecated / unused in trace decode
	GlobalSectionName       = "global"
	CoreKey                 = "core"
	ExtendedRegsSectionName = "extendregs"
	ClustersSectionName     = "clusters"

	// Core Profile Prefixes
	CPUprofileA = "Cortex-A"
	CPUprofileR = "Cortex-R"
	CPUprofileM = "Cortex-M"

	// Trace Buffer formats
	BuffFmtCS = "coresight" // coresight frame formatted.

	// ETM v4
	ETMv4Protocol = "ETM4"
	ETMv4RegCfg   = "TRCCONFIGR"
	ETMv4RegIDR   = "TRCTRACEIDR"
	ETMv4RegAuth  = "TRCAUTHSTATUS"
	ETMv4RegIDR0  = "TRCIDR0"
	ETMv4RegIDR1  = "TRCIDR1"
	ETMv4RegIDR2  = "TRCIDR2"
	ETMv4RegIDR8  = "TRCIDR8"
	ETMv4RegIDR9  = "TRCIDR9"
	ETMv4RegIDR10 = "TRCIDR10"
	ETMv4RegIDR11 = "TRCIDR11"
	ETMv4RegIDR12 = "TRCIDR12"
	ETMv4RegIDR13 = "TRCIDR13"

	// ETE
	ETEProtocol   = "ETE"
	ETERegDevArch = "TRCDEVARCH"

	// ETMv3/PTM
	ETMv3Protocol       = "ETM3"
	PTMProtocol         = "PTM1"
	PFTProtocol         = "PFT1"
	ETMv3PTMRegIDR      = "ETMIDR"
	ETMv3PTMRegCR       = "ETMCR"
	ETMv3PTMRegCCER     = "ETMCCER"
	ETMv3PTMRegTraceIDR = "ETMTRACEIDR"

	// STM/ITM
	STMProtocol = "STM"
	STMRegTCSR  = "STMTCSR"

	ITMProtocol = "ITM"
	ITMRegTCR   = "ITMTCR"
)
