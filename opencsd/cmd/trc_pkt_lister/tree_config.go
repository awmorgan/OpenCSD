package main

import (
	"errors"
	"fmt"
	"io"
	"opencsd/internal/common"
	"opencsd/internal/dcdtree"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"opencsd/internal/printers"
	"opencsd/internal/snapshot"
	"os"
	"path/filepath"
	"strings"
)

type mappedRange struct {
	start ocsd.VAddr
	end   ocsd.VAddr
	space ocsd.MemSpaceAcc
	path  string
}

func configureBuiltDecodeTree(
	tree *dcdtree.DecodeTree,
	out io.Writer,
	opts options,
) error {
	if err := configureFrameDemux(tree, out, opts); err != nil {
		return err
	}
	if err := applyAdditionalFlags(tree, opts.additionalFlags); err != nil {
		return err
	}
	return nil
}

func configureFrameDemux(tree *dcdtree.DecodeTree, out io.Writer, opts options) error {
	deformatter := tree.FrameDeformatter()
	if deformatter == nil {
		return nil
	}

	flags := deformatter.ConfigFlags()
	if opts.tpiuFormat {
		flags |= ocsd.DfrmtrHasFsyncs
	}
	if opts.hasHSync {
		flags |= ocsd.DfrmtrHasHsyncs
	}
	if opts.tpiuFormat {
		flags &^= ocsd.DfrmtrFrameMemAlign
	}
	if flags == 0 {
		flags = ocsd.DfrmtrFrameMemAlign
	}

	if opts.outRawPacked {
		flags |= ocsd.DfrmtrPackedRawOut
	}
	if opts.outRawUnpacked {
		flags |= ocsd.DfrmtrUnpackedRawOut
	}

	if err := deformatter.Configure(flags); err != nil {
		return fmt.Errorf("configure frame deformatter flags=0x%x: %w", flags, err)
	}
	if opts.outRawPacked || opts.outRawUnpacked {
		rp := printers.NewRawFramePrinter(out)
		deformatter.SetRawTraceFrame(rp)
	}
	return nil
}

func applyAdditionalFlags(tree *dcdtree.DecodeTree, flags uint32) error {
	if tree == nil || flags == 0 {
		return nil
	}

	apply := func(component any) error {
		applier, ok := component.(common.FlagApplier)
		if !ok || applier == nil {
			return nil
		}
		if err := applier.ApplyFlags(flags); err != nil {
			return fmt.Errorf("apply flags for %T with flags 0x%x: %w", component, flags, err)
		}
		return nil
	}
	var applyErr error

	tree.ForEachElement(func(_ uint8, elem *dcdtree.DecodeTreeElement) {
		if elem == nil || applyErr != nil {
			return
		}
		if err := apply(elem.FlagApplier); err != nil {
			applyErr = err
		}
	})

	return applyErr
}

func configureDecodeMode(
	out io.Writer,
	builder *snapshot.DecodeTreeBuilder,
	reader *snapshot.Reader,
	genPrinter *printers.GenericElementPrinter,
	opts options,
) error {

	if !opts.decode {
		return nil
	}

	mapper := builder.MemoryMapper()
	if mapper == nil {
		return errors.New("trace packet lister: decode mode requires a memory mapper")
	}

	if opts.memCacheDisable {
		if err := mapper.EnableCaching(false); err != nil {
			return fmt.Errorf("trace packet lister: configure memory cache disable=true failed: %w", err)
		}
	} else {
		if err := mapper.EnableCaching(true); err != nil {
			return fmt.Errorf("trace packet lister: configure memory cache disable=false failed: %w", err)
		}
		if opts.memCachePageSize != 0 || opts.memCachePageNum != 0 {
			pageSize := opts.memCachePageSize
			if pageSize == 0 {
				pageSize = memacc.DefaultPageSize
			}
			numPages := opts.memCachePageNum
			if numPages == 0 {
				numPages = uint32(memacc.DefaultNumPages)
			}
			if err := mapper.SetCacheSizes(uint16(pageSize), int(numPages), false); err != nil {
				return fmt.Errorf(
					"trace packet lister: configure memory cache sizes page_size=%d page_num=%d failed: %w",
					pageSize, numPages, err,
				)
			}
		}
	}

	mapped, err := mapMemoryRanges(mapper, opts.ssDir, reader)
	if err != nil {
		return fmt.Errorf("trace packet lister: map memory ranges failed: %w", err)
	}

	fmt.Fprintln(out, "Trace Packet Lister : Set trace element decode printer")
	if opts.testWaits > 0 {
		genPrinter.SetTestWaits(opts.testWaits)
	}
	if opts.profile {
		genPrinter.SetMute(true)
		genPrinter.SetCollectStats()
	}
	printMappedRanges(out, mapped)

	return nil
}

func mapMemoryRanges(mapper memacc.Mapper, ssDir string, reader *snapshot.Reader) ([]mappedRange, error) {
	ranges := make([]mappedRange, 0)
	seenAccessors := make(map[string]struct{})
	loadErrs := make([]string, 0)

	recordLoadErr := func(filePath string, memParams snapshot.DumpDef, format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		loadErrs = append(loadErrs, fmt.Sprintf(
			"path=%s address=0x%x offset=%d length=%d space=%q: %s",
			filepath.ToSlash(filePath),
			memParams.Address,
			memParams.Offset,
			memParams.Length,
			memParams.Space,
			msg,
		))
	}

	for _, dev := range reader.ParsedDeviceList {
		if dev == nil || !strings.EqualFold(dev.DeviceClass, "core") {
			continue
		}
		for _, memParams := range dev.DumpDefs {
			if strings.TrimSpace(memParams.Path) == "" {
				continue
			}

			filePath := filepath.Join(ssDir, memParams.Path)
			normPath := filepath.ToSlash(filePath)
			space := parseMemSpace(memParams.Space)

			f, err := os.Open(filePath)
			if err != nil {
				// Missing/unreadable external dump images are non-fatal: match snapshot builder behavior.
				continue
			}

			stat, err := f.Stat()
			if err != nil {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "stat failed: %v", err)
				continue
			}
			fileSize := stat.Size()

			if memParams.Offset >= uint64(fileSize) {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "offset beyond EOF: file_size=%d requested_offset=%d", fileSize, memParams.Offset)
				continue
			}

			var windowLen uint64
			if memParams.Length == 0 {
				windowLen = uint64(fileSize) - memParams.Offset
			} else {
				remaining := uint64(fileSize) - memParams.Offset
				windowLen = min(memParams.Length, remaining)
			}

			if windowLen == 0 {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "effective mapping length is zero")
				continue
			}

			accKey := fmt.Sprintf(
				"%s|%s|0x%x|%d|%d",
				memacc.MemSpaceString(space),
				normPath,
				memParams.Address,
				windowLen,
				memParams.Offset,
			)
			if _, seen := seenAccessors[accKey]; seen {
				_ = f.Close()
				continue
			}

			b := make([]byte, windowLen)
			if _, err := f.ReadAt(b, int64(memParams.Offset)); err != nil && err != io.EOF {
				_ = f.Close()
				recordLoadErr(filePath, memParams, "read failed: %v", err)
				continue
			}

			if err := f.Close(); err != nil {
				recordLoadErr(filePath, memParams, "close failed: %v", err)
				continue
			}

			acc := memacc.NewBufferAccessor(ocsd.VAddr(memParams.Address), b)
			acc.SetMemSpace(space)
			if err := mapper.AddAccessor(acc, ocsd.BadCSSrcID); err != nil {
				if !errors.Is(err, ocsd.ErrMemAccOverlap) {
					return nil, fmt.Errorf("add memory accessor for %s @0x%x: %w", filePath, memParams.Address, err)
				}
			}
			seenAccessors[accKey] = struct{}{}

			ranges = append(ranges, mappedRange{
				start: ocsd.VAddr(memParams.Address),
				end:   ocsd.VAddr(memParams.Address + windowLen - 1),
				space: space,
				path:  normPath,
			})
		}
	}

	if len(loadErrs) > 0 {
		return nil, fmt.Errorf("trace packet lister: snapshot memory mapping load failures:\n%s", strings.Join(loadErrs, "\n"))
	}

	return ranges, nil
}

func printMappedRanges(out io.Writer, ranges []mappedRange) {
	fmt.Fprintln(out, "Gen_Info : Mapped Memory Accessors")
	for _, r := range ranges {
		fmt.Fprintf(out, "Gen_Info : FileAcc; Range::0x%x:%x; Mem Space::%s\n", uint64(r.start), uint64(r.end), memacc.MemSpaceString(r.space))
		fmt.Fprintf(out, "Filename=%s\n", r.path)
	}
	fmt.Fprintln(out, "Gen_Info : ========================")
}
