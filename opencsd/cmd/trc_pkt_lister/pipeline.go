package main

import (
	"errors"
	"fmt"
	"io"
	"opencsd/internal/dcdtree"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
	"path/filepath"
)

func listTracePackets(out io.Writer, reader *snapshot.Reader, opts options, sourceNames []string) error {
	p, err := buildDecodePipeline(out, reader, opts)
	if err != nil {
		return err
	}
	return executeDecodePipeline(reader, p, sourceNames, opts)
}

type decodePipeline struct {
	streamOut        *synchronizedWriter
	builder          *snapshot.DecodeTreeBuilder
	tree             *dcdtree.DecodeTree
	genPrinter       *printers.GenericElementPrinter
	genAdapter       *filteredGenElemPrinter
	printersAttached int
}

type packetOutput struct {
	genPrinter       *printers.GenericElementPrinter
	genAdapter       *filteredGenElemPrinter
	printersAttached int
}

func buildDecodePipeline(
	out io.Writer,
	reader *snapshot.Reader,
	opts options,
) (*decodePipeline, error) {
	streamOut := &synchronizedWriter{w: out}

	builder, tree, err := buildSnapshotDecodeTree(reader, opts)
	if err != nil {
		return nil, err
	}

	if err := configureBuiltDecodeTree(tree, streamOut, opts); err != nil {
		return nil, err
	}

	output := configurePacketOutput(streamOut, tree, opts)

	return &decodePipeline{
		streamOut:        streamOut,
		builder:          builder,
		tree:             tree,
		genPrinter:       output.genPrinter,
		genAdapter:       output.genAdapter,
		printersAttached: output.printersAttached,
	}, nil
}

func buildSnapshotDecodeTree(
	reader *snapshot.Reader,
	opts options,
) (*snapshot.DecodeTreeBuilder, *dcdtree.DecodeTree, error) {
	builder := snapshot.NewDecodeTreeBuilder(reader)
	packetProcOnly := !opts.decode

	tree, err := builder.Build(opts.srcName, packetProcOnly)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"trace packet lister: failed to create decode tree for source %s: %w",
			opts.srcName, err,
		)
	}
	if tree == nil {
		return nil, nil, errors.New("trace packet lister: no supported protocols found")
	}

	return builder, tree, nil
}

func configurePacketOutput(
	out io.Writer,
	tree *dcdtree.DecodeTree,
	opts options,
) packetOutput {
	genPrinter := printers.NewGenericElementPrinter(out)
	genAdapter := &filteredGenElemPrinter{
		printer:      genPrinter,
		allSourceIDs: opts.allSourceIDs,
		validIDs:     makeIDSet(opts.idList),
	}

	printersAttached := 0
	if !opts.decodeOnly {
		printersAttached = attachPacketPrinters(out, tree, opts)
	}

	return packetOutput{
		genPrinter:       genPrinter,
		genAdapter:       genAdapter,
		printersAttached: printersAttached,
	}
}

func runSingleSession(
	out io.Writer,
	tree *dcdtree.DecodeTree,
	fileName string,
	sink *filteredGenElemPrinter,
	genPrinter *printers.GenericElementPrinter,
	opts options,
) error {
	return processInputFilePull(out, tree, fileName, sink, genPrinter, opts)
}

func runMultiSession(
	out io.Writer,
	reader *snapshot.Reader,
	tree *dcdtree.DecodeTree,
	sourceNames []string,
	sink *filteredGenElemPrinter,
	genPrinter *printers.GenericElementPrinter,
	opts options,
) error {
	total := len(sourceNames)
	for i, sourceName := range sourceNames {
		fmt.Fprintf(out, "####### Multi Session decode: Buffer %d of %d; Source name = %s.\n\n", i+1, total, sourceName)
		srcTree, ok := reader.SourceTrees[sourceName]
		if !ok || srcTree == nil || srcTree.BufferInfo == nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s - buffer not found. Aborting.\n\n", sourceName)
			break
		}
		binFile := filepath.Join(reader.SnapshotPath, srcTree.BufferInfo.DataFileName)
		if err := processInputFilePull(out, tree, binFile, sink, genPrinter, opts); err != nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s failed. Aborting.\n\n", sourceName)
			return err
		}
		fmt.Fprintf(out, "####### Buffer %d : %s Complete\n\n", i+1, sourceName)
	}
	return nil
}
