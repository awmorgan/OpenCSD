package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
)

type dummyMemAcc struct{}

func (d *dummyMemAcc) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	return 0, nil, ocsd.ErrMemNacc // No memory mapped, always return NACC
}
func (d *dummyMemAcc) InvalidateMemAccCache(csTraceID uint8) {}

type dummyInstrDec struct{}

func (d *dummyInstrDec) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	return ocsd.ErrUnsuppDecodePkt
}

var (
	ssDir         = flag.String("ss_dir", "", "Set the directory path to a trace snapshot")
	srcName       = flag.String("src_name", "", "List packets from a given snapshot source name")
	decode        = flag.Bool("decode", false, "Full decode of the packets from the trace snapshot")
	logStdout     = flag.Bool("logstdout", true, "Output to stdout")
	logFile       = flag.String("logfile", "", "Output to specified file")
	dstreamFormat = flag.Bool("dstream_format", false, "Input is DSTREAM framed")
	stats         = flag.Bool("stats", false, "Output packet processing statistics")
	noTimePrint   = flag.Bool("no_time_print", false, "Do not output elapsed time")
)

func main() {
	flag.Parse()

	if *ssDir == "" {
		fmt.Fprintf(os.Stderr, "Error: -ss_dir is required\n")
		os.Exit(1)
	}

	var out io.Writer = os.Stdout
	if *logFile != "" {
		f, err := os.Create(*logFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
	}

	fmt.Fprintf(out, "Trace Packet Lister: CS Decode library testing (Go Port)\n")
	fmt.Fprintf(out, "--------------------------------------------------------\n\n")
	fmt.Fprintf(out, "Trace Packet Lister : reading snapshot from path %s\n", *ssDir)

	reader := snapshot.NewReader()
	reader.SetSnapshotDir(*ssDir)
	reader.Verbose = true

	if !reader.ReadSnapShot() {
		fmt.Fprintf(out, "Trace Packet Lister : Failed to read snapshot\n")
		os.Exit(1)
	}

	builder := snapshot.NewCreateDcdTreeFromSnapShot(reader)

	targetSource := *srcName
	if targetSource == "" {
		if reader.ParsedTrace == nil || len(reader.ParsedTrace.TraceBuffers) == 0 {
			fmt.Fprintf(out, "Trace Packet Lister : No trace source buffer names found\n")
			os.Exit(1)
		}
		targetSource = reader.ParsedTrace.TraceBuffers[0].BufferName
	}

	fmt.Fprintf(out, "Using %s as trace source\n", targetSource)

	if !builder.CreateDecodeTree(targetSource, !*decode) {
		fmt.Fprintf(out, "Trace Packet Lister : Failed to create decode tree for source %s\n", targetSource)
		os.Exit(1)
	}

	tree := builder.GetDecodeTree()

	// Attach printers
	genElemPrinter := printers.NewGenericElementPrinter(out)
	genElemPrinter.SetCollectStats()
	if *decode {
		tree.SetGenTraceElemOutI(genElemPrinter)
		tree.SetMemAccessI(&dummyMemAcc{})
		tree.SetInstrDecoder(&dummyInstrDec{})
		fmt.Fprintf(out, "Trace Packet Lister : Set trace element decode printer (with dummy MemAcc/InstrDec)\n")
	}

	binFile := builder.GetBufferFileName()
	file, err := os.Open(binFile)
	if err != nil {
		fmt.Fprintf(out, "Trace Packet Lister : Error : Unable to open trace buffer %s: %v\n", binFile, err)
		os.Exit(1)
	}
	defer file.Close()

	start := time.Now()
	var traceIndex uint32 = 0
	buf := make([]byte, 1024)

	for {
		header := 0
		if *dstreamFormat {
			header = 0 // Actually in DSTREAM, it's 512-8 bytes blocks. We simplify here.
		}

		n, err := file.Read(buf)
		if n > 0 {
			_, resp := tree.TraceDataIn(ocsd.OpData, ocsd.TrcIndex(traceIndex), buf[:n])
			if ocsd.DataRespIsFatal(resp) {
				fmt.Fprintf(out, "Trace Packet Lister : Data Path fatal error\n")
				break
			}
			traceIndex += uint32(n)
		}

		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Fprintf(out, "Error reading trace file: %v\n", err)
			break
		}
		_ = header
	}

	tree.TraceDataIn(ocsd.OpEOT, 0, nil)

	elapsed := time.Since(start).Seconds()

	fmt.Fprintf(out, "Trace Packet Lister : Trace buffer done, processed %d bytes", traceIndex)
	if !*noTimePrint {
		fmt.Fprintf(out, " in %.8f seconds.\n", elapsed)
	} else {
		fmt.Fprintf(out, ".\n")
	}

	if *stats {
		genElemPrinter.PrintStats()
	}

	_ = common.TraceElement{}
}
