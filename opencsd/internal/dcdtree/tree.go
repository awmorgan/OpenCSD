package dcdtree

import (
	"context"
	"errors"
	"fmt"
	"io"
	"opencsd/internal/common"
	"opencsd/internal/demux"

	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"slices"
)

var (
	// ErrCreateFullDecoder indicates full decoder creation failed.
	ErrCreateFullDecoder = errors.New("create full decoder failed")
	// ErrCreatePacketProcessor indicates packet processor creation failed.
	ErrCreatePacketProcessor = errors.New("create packet processor failed")
	// ErrCreateDecodeTree indicates decode-tree creation failed.
	ErrCreateDecodeTree = errors.New("create decode tree failed")
)

// DecodeTree manages the decoding of trace data from a single trace sink.
//
// IMPORTANT: DecodeTree is strictly thread-unsafe. The underlying elements map
// (decodeElements) is written to during CreateFullDecoder/RemoveDecoder
// and read from during TraceDataIn. Concurrent configuration and data processing
// will result in a runtime panic.
type DecodeTree struct {
	treeType         ocsd.DcdTreeSrc
	frameDeformatter *demux.FrameDeformatter
	decodeElements   map[uint8]*DecodeTreeElement

	defaultMapper memacc.Mapper
	createdMapper bool

	decoderRoot ocsd.TraceDecoder
}

// NewDecodeTree creates a new Trace Decode Tree using the supplied decoder registry.
// A non-nil registry is required.
func NewDecodeTree(srcType ocsd.DcdTreeSrc, formatterCfgFlags uint32) (*DecodeTree, error) {
	dt := &DecodeTree{
		treeType:       srcType,
		decodeElements: make(map[uint8]*DecodeTreeElement),
	}

	if srcType == ocsd.TrcSrcFrameFormatted {
		dt.frameDeformatter = demux.NewFrameDeformatter()
		if err := dt.frameDeformatter.Configure(formatterCfgFlags); err != nil {
			return nil, fmt.Errorf("%w: configure frame deformatter: %w", ErrCreateDecodeTree, err)
		}
		dt.decoderRoot = dt.frameDeformatter
	}

	return dt, nil
}

// Destroy cleans up memory accessors (although GC does mostly).
func (dt *DecodeTree) Destroy() {
	dt.decodeElements = nil
	dt.frameDeformatter = nil
	if dt.createdMapper && dt.defaultMapper != nil {
		dt.defaultMapper = nil
	}
}

// TraceDataIn handles incoming raw byte trace streams into the tree.
func (dt *DecodeTree) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, data []byte) (uint32, error) {
	return dt.TraceDataInContext(context.Background(), op, index, data)
}

// TraceDataInContext handles incoming raw byte trace streams into the tree with cancellation support.
func (dt *DecodeTree) TraceDataInContext(ctx context.Context, op ocsd.DatapathOp, index ocsd.TrcIndex, data []byte) (uint32, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
	}

	const processChunk = 64 * 1024
	callTraceData := func(proc ocsd.TraceDecoder, op ocsd.DatapathOp, index ocsd.TrcIndex, data []byte) (uint32, error) {
		switch op {
		case ocsd.OpData:
			return proc.Write(index, data)
		case ocsd.OpEOT:
			return 0, proc.Close()
		case ocsd.OpFlush:
			return 0, proc.Flush()
		case ocsd.OpReset:
			return 0, proc.Reset(index)
		default:
			return 0, ocsd.ErrInvalidParamVal
		}
	}

	processWithContext := func(proc ocsd.TraceDecoder) (uint32, error) {
		if proc == nil {
			return 0, ocsd.ErrNotInit
		}
		if ctx == nil || op != ocsd.OpData || len(data) <= processChunk {
			processed, err := callTraceData(proc, op, index, data)
			return processed, err
		}

		var total uint32
		for offset := 0; offset < len(data); {
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			default:
			}

			end := min(offset+processChunk, len(data))

			chunkIdx := index + ocsd.TrcIndex(offset)
			amt, err := callTraceData(proc, op, chunkIdx, data[offset:end])
			total += amt
			if !ocsd.DataRespIsCont(ocsd.DataRespFromErr(err)) {
				return total, err
			}
			if amt == 0 {
				break
			}
			offset += int(amt)
		}
		return total, nil
	}

	if dt.decoderRoot != nil {
		return processWithContext(dt.decoderRoot)
	}

	// Unformatted single trace source fallback
	if dt.treeType == ocsd.TrcSrcSingle {
		elem := dt.decodeElements[0]
		if elem != nil && elem.DataIn != nil {
			return processWithContext(elem.DataIn)
		}
	}
	return 0, ocsd.ErrNotInit
}

// AddPullDecoder registers decoder input routing and pull-based output iteration into the tree.
func (dt *DecodeTree) AddPullDecoder(routeID uint8, name string, protocol ocsd.TraceProtocol, pktIn ocsd.TraceDecoder, iter ocsd.TraceIterator, flagApplier common.FlagApplier) error {
	if dt.treeType == ocsd.TrcSrcSingle {
		routeID = 0
	}
	if routeID >= 0x80 {
		return ocsd.ErrInvalidID
	}
	if pktIn == nil && iter == nil {
		return ocsd.ErrNotInit
	}

	if elem, exists := dt.decodeElements[routeID]; exists {
		if pktIn != nil && elem.DataIn != nil {
			return ocsd.ErrAttachTooMany
		}
		if iter != nil && elem.Iterator != nil {
			return ocsd.ErrAttachTooMany
		}
		if pktIn != nil {
			elem.DataIn = pktIn
			if dt.frameDeformatter != nil {
				dt.frameDeformatter.SetIDStream(routeID, pktIn)
			}
		}
		elem.Iterator = iter
		if elem.FlagApplier == nil {
			elem.FlagApplier = flagApplier
		}
		if elem.Protocol == ocsd.ProtocolUnknown {
			elem.Protocol = protocol
		}
		if elem.DecoderTypeName == "" {
			elem.DecoderTypeName = name
		}
		return nil
	}

	// No decoder manager is needed for direct injection.
	elem := NewDecodeTreeElement(name, flagApplier, pktIn, iter, true)
	elem.Protocol = protocol

	dt.decodeElements[routeID] = elem
	if dt.frameDeformatter != nil && pktIn != nil {
		dt.frameDeformatter.SetIDStream(routeID, pktIn)
	}
	return nil
}

func (dt *DecodeTree) nextFromElement(elem *DecodeTreeElement) (*ocsd.TraceElement, error) {
	if elem == nil {
		return nil, io.EOF
	}
	if elem.Iterator != nil {
		return elem.Iterator.Next()
	}
	return nil, io.EOF
}

// Next returns the next available generic trace element from registered pull decoders.
func (dt *DecodeTree) Next() (*ocsd.TraceElement, error) {
	ids := dt.sortedElementIDs()
	if len(ids) == 0 {
		return nil, io.EOF
	}

	if dt.treeType == ocsd.TrcSrcSingle || len(ids) == 1 {
		return dt.nextFromElement(dt.decodeElements[ids[0]])
	}

	for _, csID := range ids {
		elem := dt.decodeElements[csID]
		if elem == nil || elem.Iterator == nil {
			continue
		}
		trcElem, err := elem.Iterator.Next()
		if errors.Is(err, io.EOF) {
			continue
		}
		return trcElem, err
	}

	return nil, io.EOF
}

// RemoveDecoder removes a decoder mapped to the given CSID.
func (dt *DecodeTree) RemoveDecoder(csID uint8) {
	routeID := csID
	if dt.treeType == ocsd.TrcSrcSingle {
		routeID = 0
	}

	if dt.frameDeformatter != nil {
		dt.frameDeformatter.SetIDStream(routeID, nil)
	}
	delete(dt.decodeElements, routeID)
}

// FrameDeformatter returns the active frame demux.
func (dt *DecodeTree) FrameDeformatter() *demux.FrameDeformatter {
	return dt.frameDeformatter
}

// FirstElement provides iteration entry point.
func (dt *DecodeTree) FirstElement() (uint8, *DecodeTreeElement) {
	ids := dt.sortedElementIDs()
	if len(ids) == 0 {
		return 0, nil
	}
	id := ids[0]
	return id, dt.decodeElements[id]
}

// ForEachElement iterates all registered decode tree elements.
func (dt *DecodeTree) ForEachElement(fn func(csID uint8, elem *DecodeTreeElement)) {
	if fn == nil {
		return
	}
	for _, csID := range dt.sortedElementIDs() {
		elem := dt.decodeElements[csID]
		fn(csID, elem)
	}
}

func (dt *DecodeTree) sortedElementIDs() []uint8 {
	ids := make([]uint8, 0, len(dt.decodeElements))
	for id := range dt.decodeElements {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
