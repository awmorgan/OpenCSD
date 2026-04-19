package main

import (
	"flag"
	"fmt"
	"io"
	"strconv"

	"opencsd/internal/ocsd"
)

const defaultLogFile = "trc_pkt_lister.ppl"

type options struct {
	ssDir            string
	ssVerbose        bool
	srcName          string
	multiSession     bool
	decode           bool
	decodeOnly       bool
	pktMon           bool
	stats            bool
	profile          bool
	noTimePrint      bool
	outRawPacked     bool
	outRawUnpacked   bool
	dstreamFormat    bool
	tpiuFormat       bool
	hasHSync         bool
	testWaits        int
	allSourceIDs     bool
	idList           []uint8
	additionalFlags  uint32
	memCacheDisable  bool
	memCachePageSize uint32
	memCachePageNum  uint32
	logStdout        bool
	logStderr        bool
	logFile          bool
	logFileName      string
	help             bool

	// parse-only flag state used to finalize composite options.
	flagDecodeOnly   bool
	flagTPIU         bool
	flagTPIUHSync    bool
	flagDirectBrCond bool
	flagStrictBrCond bool
	flagRangeCont    bool
	flagHaltErr      bool
	flagSrcAddrN     bool
	flagAA64Opcode   bool
	flagLogStdout    bool
	flagLogStderr    bool
	flagLogFile      bool
	flagLogFileName  string
}

// idListValue implements flag.Value to allow multiple -id flags.
type idListValue []uint8

func (i *idListValue) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *idListValue) Set(value string) error {
	v, err := strconv.ParseUint(value, 0, 8)
	if err != nil {
		return fmt.Errorf("invalid ID number %s", value)
	}
	id := uint8(v)
	if !ocsd.IsValidCSSrcID(id) {
		return fmt.Errorf("invalid ID number 0x%x", id)
	}
	*i = append(*i, id)
	return nil
}

type uint32Value struct {
	target *uint32
}

func (u *uint32Value) String() string {
	if u == nil || u.target == nil {
		return "0"
	}
	return strconv.FormatUint(uint64(*u.target), 10)
}

func (u *uint32Value) Set(value string) error {
	v, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return err
	}
	*u.target = uint32(v)
	return nil
}

func (o *options) finalizeParsedFlags() {
	if o.flagDecodeOnly {
		o.decodeOnly = true
		o.decode = true
	}

	if o.flagTPIU {
		o.tpiuFormat = true
	}
	if o.flagTPIUHSync {
		o.tpiuFormat = true
		o.hasHSync = true
	}

	if o.flagDirectBrCond {
		o.additionalFlags |= ocsd.OpflgNUncondDirBrChk
	}
	if o.flagStrictBrCond {
		o.additionalFlags |= ocsd.OpflgStrictNUncondBrChk
	}
	if o.flagRangeCont {
		o.additionalFlags |= ocsd.OpflgChkRangeContinue
	}
	if o.flagHaltErr {
		o.additionalFlags |= ocsd.OpflgPktdecHaltBadPkts
	}
	if o.flagSrcAddrN {
		o.additionalFlags |= ocsd.OpflgPktdecSrcAddrNAtoms
	}
	if o.flagAA64Opcode {
		o.additionalFlags |= ocsd.OpflgPktdecAA64OpcodeChk
	}

	if len(o.idList) > 0 {
		o.allSourceIDs = false
	}

	switch {
	case o.flagLogStdout:
		o.logStdout = true
		o.logStderr = false
		o.logFile = false
	case o.flagLogStderr:
		o.logStdout = false
		o.logStderr = true
		o.logFile = false
	case o.flagLogFileName != "":
		o.logFileName = o.flagLogFileName
		o.logStdout = false
		o.logStderr = false
		o.logFile = true
	case o.flagLogFile:
		o.logStdout = false
		o.logStderr = false
		o.logFile = true
	}
}

func parseOptions(args []string) (options, error) {
	opts := options{
		allSourceIDs: true,
		logStdout:    true,
		logFile:      true,
		logFileName:  defaultLogFile,
	}

	fs := flag.NewFlagSet("Trace Packet Lister", flag.ContinueOnError)
	fs.Usage = func() {}

	fs.StringVar(&opts.ssDir, "ss_dir", "", "Set the directory path to a trace snapshot")
	fs.BoolVar(&opts.ssVerbose, "ss_verbose", false, "Verbose output when reading the snapshot")
	fs.StringVar(&opts.srcName, "src_name", "", "List packets from a given snapshot source name")
	fs.BoolVar(&opts.multiSession, "multi_session", false, "Decode all source buffers with same config")
	fs.BoolVar(&opts.decode, "decode", false, "Full decode of packets from snapshot")
	fs.BoolVar(&opts.pktMon, "pkt_mon", false, "Enable packet monitor")
	fs.BoolVar(&opts.stats, "stats", false, "Output packet processing statistics")
	fs.BoolVar(&opts.profile, "profile", false, "Profile output")
	fs.BoolVar(&opts.noTimePrint, "no_time_print", false, "Do not output elapsed time")
	fs.BoolVar(&opts.outRawPacked, "o_raw_packed", false, "Output raw packed trace frames")
	fs.BoolVar(&opts.outRawUnpacked, "o_raw_unpacked", false, "Output raw unpacked trace data per ID")
	fs.BoolVar(&opts.dstreamFormat, "dstream_format", false, "Input is DSTREAM framed")
	fs.IntVar(&opts.testWaits, "test_waits", 0, "Wait count value")
	fs.BoolVar(&opts.memCacheDisable, "macc_cache_disable", false, "Disable memory cache")

	fs.Var((*idListValue)(&opts.idList), "id", "Set an ID to list (may be used multiple times)")

	fs.BoolVar(&opts.flagDecodeOnly, "decode_only", false, "Decode only, no packet printer output")
	fs.BoolVar(&opts.flagTPIU, "tpiu", false, "Input from TPIU - sync by FSYNC")
	fs.BoolVar(&opts.flagTPIUHSync, "tpiu_hsync", false, "Input from TPIU - sync by FSYNC and HSYNC")

	fs.BoolVar(&opts.flagDirectBrCond, "direct_br_cond", false, "Additional flag: direct_br_cond")
	fs.BoolVar(&opts.flagStrictBrCond, "strict_br_cond", false, "Additional flag: strict_br_cond")
	fs.BoolVar(&opts.flagRangeCont, "range_cont", false, "Additional flag: range_cont")
	fs.BoolVar(&opts.flagHaltErr, "halt_err", false, "Additional flag: halt_err")
	fs.BoolVar(&opts.flagSrcAddrN, "src_addr_n", false, "Additional flag: src_addr_n")
	fs.BoolVar(&opts.flagAA64Opcode, "aa64_opcode_chk", false, "Additional flag: aa64_opcode_chk")

	fs.Var(&uint32Value{target: &opts.memCachePageSize}, "macc_cache_p_size", "Memory cache page size")
	fs.Var(&uint32Value{target: &opts.memCachePageNum}, "macc_cache_p_num", "Memory cache page number")

	fs.BoolVar(&opts.flagLogStdout, "logstdout", false, "Output to stdout")
	fs.BoolVar(&opts.flagLogStderr, "logstderr", false, "Output to stderr")
	fs.BoolVar(&opts.flagLogFile, "logfile", false, "Output to default file")
	fs.StringVar(&opts.flagLogFileName, "logfilename", "", "Output to specific file name")

	fs.BoolVar(&opts.help, "help", false, "Show help")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			opts.help = true
			return opts, nil
		}
		return opts, fmt.Errorf("trace packet lister: error parsing flags: %w", err)
	}

	if opts.help {
		opts.help = true
		return opts, nil
	}

	opts.finalizeParsedFlags()
	return opts, nil
}

func printHelp(out io.Writer) {
	fmt.Fprintln(out, "Trace Packet Lister - commands")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Snapshot:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-ss_dir <dir>       Set the directory path to a trace snapshot")
	fmt.Fprintln(out, "-ss_verbose         Verbose output when reading the snapshot")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Decode:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-id <n>             Set an ID to list (may be used multiple times)")
	fmt.Fprintln(out, "-src_name <name>    List packets from a given snapshot source name")
	fmt.Fprintln(out, "-multi_session      Decode all source buffers with same config")
	fmt.Fprintln(out, "-dstream_format     Input is DSTREAM framed")
	fmt.Fprintln(out, "-tpiu               Input from TPIU - sync by FSYNC")
	fmt.Fprintln(out, "-tpiu_hsync         Input from TPIU - sync by FSYNC and HSYNC")
	fmt.Fprintln(out, "-decode             Full decode of packets from snapshot")
	fmt.Fprintln(out, "-decode_only        Decode only, no packet printer output")
	fmt.Fprintln(out, "-o_raw_packed       Output raw packed trace frames")
	fmt.Fprintln(out, "-o_raw_unpacked     Output raw unpacked trace data per ID")
	fmt.Fprintln(out, "-stats              Output packet processing statistics")
	fmt.Fprintln(out, "-no_time_print      Do not output elapsed time")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Output:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-logstdout          Output to stdout")
	fmt.Fprintln(out, "-logstderr          Output to stderr")
	fmt.Fprintln(out, "-logfile            Output to default file")
	fmt.Fprintln(out, "-logfilename <name> Output to file <name>")
}
