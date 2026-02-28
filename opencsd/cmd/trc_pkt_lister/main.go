package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
)

// memAccAdapter adapts memacc.Mapper to common.TargetMemAccess
type memAccAdapter struct {
	mapper memacc.Mapper
}

func (m *memAccAdapter) ReadTargetMemory(address ocsd.VAddr, csTraceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, ocsd.Err) {
	buf := make([]byte, reqBytes)
	readBytes := reqBytes
	err := m.mapper.ReadTargetMemory(address, csTraceID, memSpace, &readBytes, buf)
	return readBytes, buf[:readBytes], err
}

func (m *memAccAdapter) InvalidateMemAccCache(csTraceID uint8) {
	m.mapper.InvalidateMemAccCache(csTraceID)
}

var (
	ssDir       = flag.String("ss_dir", "", "Set the directory path to a trace snapshot")
	srcName     = flag.String("src_name", "", "List packets from a given snapshot source name")
	decode      = flag.Bool("decode", false, "Full decode of the packets from the trace snapshot")
	logFile     = flag.String("logfile", "", "Output to specified file")
	stats       = flag.Bool("stats", false, "Output packet processing statistics")
	noTimePrint = flag.Bool("no_time_print", false, "Do not output elapsed time")
)

type dummyInstrDec struct{}

func (d *dummyInstrDec) DecodeInstruction(instrInfo *ocsd.InstrInfo) ocsd.Err {
	return ocsd.ErrUnsuppDecodePkt
}

type genElemOutAdapter struct {
	printer *printers.GenericElementPrinter
}

func (g *genElemOutAdapter) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) ocsd.DatapathResp {
	return g.printer.TraceElemIn(indexSOP, trcChanID, elem)
}

func main() {
	flag.Parse()

	if *ssDir == "" {
		log.Fatalf("Error: -ss_dir is required\n")
	}

	var out io.Writer = os.Stdout
	if *logFile != "" {
		f, err := os.Create(*logFile)
		if err != nil {
			log.Fatalf("Failed to open log file: %v\n", err)
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
		log.Fatalf("Trace Packet Lister : Failed to read snapshot\n")
	}

	builder := snapshot.NewCreateDcdTreeFromSnapShot(reader)

	targetSource := *srcName
	if targetSource == "" {
		if reader.ParsedTrace == nil || len(reader.ParsedTrace.TraceBuffers) == 0 {
			log.Fatalf("Trace Packet Lister : No trace source buffer names found\n")
		}
		targetSource = reader.ParsedTrace.TraceBuffers[0].BufferName
	}

	fmt.Fprintf(out, "Using %s as trace source\n", targetSource)

	// Create Decode Tree
	if !builder.CreateDecodeTree(targetSource, !*decode) {
		log.Fatalf("Trace Packet Lister : Failed to create decode tree for source %s\n", targetSource)
	}

	tree := builder.GetDecodeTree()

	// Memory Setup
	mapper := memacc.NewGlobalMapper()
	tree.SetMemAccessI(&memAccAdapter{mapper: mapper})

	// Scan parsed devices for memory dumps
	for _, dev := range reader.ParsedDeviceList {
		if strings.HasPrefix(dev.DeviceTypeName, "core") {
			for _, memParams := range dev.DumpDefs {
				path := filepath.Join(*ssDir, memParams.Path)
				address := memParams.Address

				b, err := os.ReadFile(path)
				if err == nil {
					accessor := memacc.NewBufferAccessor(ocsd.VAddr(address), b)
					mapper.AddAccessor(accessor, 0)
				}
			}
		}
	}

	// Output Printer setup
	genElemPrinter := printers.NewGenericElementPrinter(out)
	genElemPrinter.SetCollectStats()

	// Adapter for TraceElemOut
	printerAdapter := &genElemOutAdapter{printer: genElemPrinter}

	// Attach full decoder interfaces if decoding
	if *decode {
		tree.SetGenTraceElemOutI(printerAdapter)
		tree.SetInstrDecoder(&dummyInstrDec{})
	} else {
		// If just packet listing, we would ideally attach protocol printers
		// but since we haven't ported all protocol printers, we fallback.
		fmt.Fprintf(out, "Warning: Protocol packet printing alone is unsupported yet. Try adding -decode.\n")
	}

	binFile := builder.GetBufferFileName()
	file, err := os.Open(binFile)
	if err != nil {
		log.Fatalf("Trace Packet Lister : Error : Unable to open trace buffer %s: %v\n", binFile, err)
	}
	defer file.Close()

	start := time.Now()
	var traceIndex uint32 = 0
	buf := make([]byte, 1024)

	// Stream Trace Data
	for {
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
	}

	tree.TraceDataIn(ocsd.OpEOT, ocsd.TrcIndex(traceIndex), nil)

	elapsed := time.Since(start).Seconds()

	fmt.Fprintf(out, "Trace Packet Lister : Trace buffer done, processed %d bytes", traceIndex)
	if !*noTimePrint {
		fmt.Fprintf(out, " in %.8f seconds.\n", elapsed)
	} else {
		fmt.Fprintf(out, ".\n")
	}

	if *stats && *decode {
		genElemPrinter.PrintStats()
	}
}
