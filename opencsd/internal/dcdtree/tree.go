package dcdtree

import (
	"context"
	"errors"
	"fmt"
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

	decoderRoot ocsd.TrcDataProcessor
	genElemOut  ocsd.GenElemProcessor
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
func (dt *DecodeTree) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, data []byte) (uint32, ocsd.DatapathResp, error) {
	return dt.TraceDataInContext(context.Background(), op, index, data)
}

// TraceDataInContext handles incoming raw byte trace streams into the tree with cancellation support.
func (dt *DecodeTree) TraceDataInContext(ctx context.Context, op ocsd.DatapathOp, index ocsd.TrcIndex, data []byte) (uint32, ocsd.DatapathResp, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return 0, ocsd.RespFatalSysErr, ctx.Err()
		default:
		}
	}

	const processChunk = 64 * 1024
	processWithContext := func(proc ocsd.TrcDataProcessor) (uint32, ocsd.DatapathResp, error) {
		if proc == nil {
			return 0, ocsd.RespFatalNotInit, nil
		}
		if ctx == nil || op != ocsd.OpData || len(data) <= processChunk {
			return proc.TraceDataIn(op, index, data)
		}

		var total uint32
		resp := ocsd.RespCont
		for offset := 0; offset < len(data); {
			select {
			case <-ctx.Done():
				return total, ocsd.RespFatalSysErr, ctx.Err()
			default:
			}

			end := min(offset+processChunk, len(data))

			chunkIdx := index + ocsd.TrcIndex(offset)
			amt, chunkResp, err := proc.TraceDataIn(op, chunkIdx, data[offset:end])
			total += amt
			resp = chunkResp
			if err != nil || !ocsd.DataRespIsCont(chunkResp) {
				return total, chunkResp, err
			}
			if amt == 0 {
				break
			}
			offset += int(amt)
		}
		return total, resp, nil
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
	return 0, ocsd.RespFatalNotInit, nil
}

// AddDecoder registers an already-instantiated decoder into the tree.
func (dt *DecodeTree) AddDecoder(routeID uint8, name string, protocol ocsd.TraceProtocol, pktIn ocsd.TrcDataProcessor, handle any) error {
	if dt.treeType == ocsd.TrcSrcSingle {
		routeID = 0
	}
	if routeID >= 0x80 {
		return ocsd.ErrInvalidID
	}

	if _, exists := dt.decodeElements[routeID]; exists {
		return ocsd.ErrAttachTooMany
	}

	// No decoder manager is needed for direct injection.
	elem := NewDecodeTreeElement(name, handle, pktIn, true)
	elem.Protocol = protocol

	dt.decodeElements[routeID] = elem
	if dt.frameDeformatter != nil && pktIn != nil {
		dt.frameDeformatter.SetIDStream(routeID, pktIn)
	}
	dt.attachElementDependencies(elem)

	return nil
}

func (dt *DecodeTree) attachElementDependencies(elem *DecodeTreeElement) {
	if dt.genElemOut != nil {
		dt.wireTraceElemOut(elem, dt.genElemOut)
	}
}

func (dt *DecodeTree) wireTraceElemOut(elem *DecodeTreeElement, outI ocsd.GenElemProcessor) {
	if elem == nil || outI == nil {
		return
	}
	if owner, ok := elem.DecoderHandle.(traceElemWiringOwner); ok {
		owner.SetTraceElemOut(outI)
		return
	}
	// Compatibility fallback while migrating away from function pointer extraction.
	if elem.SetTraceElemOut != nil {
		elem.SetTraceElemOut(outI)
	}
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

// SetGenTraceElemOutI attaches a sink for generic trace element outputs generated by the entire tree.
func (dt *DecodeTree) SetGenTraceElemOutI(outI ocsd.GenElemProcessor) {
	dt.genElemOut = outI
	for _, elem := range dt.decodeElements {
		dt.wireTraceElemOut(elem, outI)
	}
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
