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

	decoderRoot ocsd.TrcDataProcessorExplicit
	genElemOut  ocsd.GenElemProcessor
}

type teeGenElemOut struct {
	primary   ocsd.GenElemProcessor
	secondary ocsd.GenElemProcessor
}

func (t *teeGenElemOut) TraceElemIn(indexSOP ocsd.TrcIndex, trcChanID uint8, elem *ocsd.TraceElement) error {
	if t.primary != nil {
		err := t.primary.TraceElemIn(indexSOP, trcChanID, elem)
		if !ocsd.IsDataContErr(err) {
			return err
		}
	}
	if t.secondary != nil {
		return t.secondary.TraceElemIn(indexSOP, trcChanID, elem)
	}
	return nil
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
	callTraceData := func(proc ocsd.TrcDataProcessorExplicit, op ocsd.DatapathOp, index ocsd.TrcIndex, data []byte) (uint32, error) {
		switch op {
		case ocsd.OpData:
			return proc.TraceData(index, data)
		case ocsd.OpEOT:
			return 0, proc.TraceDataEOT()
		case ocsd.OpFlush:
			return 0, proc.TraceDataFlush()
		case ocsd.OpReset:
			return 0, proc.TraceDataReset(index)
		default:
			return 0, ocsd.ErrInvalidParamVal
		}
	}

	processWithContext := func(proc ocsd.TrcDataProcessorExplicit) (uint32, error) {
		if proc == nil {
			return 0, ocsd.ErrNotInit
		}
		if ctx == nil || op != ocsd.OpData || len(data) <= processChunk {
			processed, err := callTraceData(proc, op, index, data)
			if !ocsd.IsDataContErr(err) {
				return processed, err
			}
			if pullErr := dt.drainPullIteratorsToSink(); pullErr != nil {
				return processed, pullErr
			}
			return processed, nil
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
			if pullErr := dt.drainPullIteratorsToSink(); pullErr != nil {
				return total, pullErr
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

// AddDecoder registers an already-instantiated decoder into the tree for routing only.
func (dt *DecodeTree) AddDecoder(routeID uint8, name string, protocol ocsd.TraceProtocol, pktIn ocsd.TrcDataProcessorExplicit, flagApplier common.FlagApplier) error {
	return dt.addDecoder(routeID, name, protocol, pktIn, nil, flagApplier, nil)
}

// AddPullDecoder registers a pull-based iterator decoder into the tree.
func (dt *DecodeTree) AddPullDecoder(routeID uint8, name string, protocol ocsd.TraceProtocol, iter ocsd.TraceIterator) error {
	if dt.treeType == ocsd.TrcSrcSingle {
		routeID = 0
	}
	if routeID >= 0x80 {
		return ocsd.ErrInvalidID
	}
	if iter == nil {
		return ocsd.ErrNotInit
	}

	if elem, exists := dt.decodeElements[routeID]; exists {
		elem.Iterator = iter
		if elem.Protocol == ocsd.ProtocolUnknown {
			elem.Protocol = protocol
		}
		if elem.DecoderTypeName == "" {
			elem.DecoderTypeName = name
		}
		return nil
	}

	return dt.addDecoder(routeID, name, protocol, nil, iter, nil, nil)
}

// AddWiredDecoder registers an already-instantiated decoder into the tree with explicit
// late trace-sink wiring support.
func (dt *DecodeTree) AddWiredDecoder(routeID uint8, name string, protocol ocsd.TraceProtocol, pktIn ocsd.TrcDataProcessorExplicit, flagApplier common.FlagApplier, wiring wireTraceElemFn) error {
	return dt.addDecoder(routeID, name, protocol, pktIn, nil, flagApplier, wiring)
}

func (dt *DecodeTree) addDecoder(routeID uint8, name string, protocol ocsd.TraceProtocol, pktIn ocsd.TrcDataProcessorExplicit, iter ocsd.TraceIterator, flagApplier common.FlagApplier, wiring wireTraceElemFn) error {
	if dt.treeType == ocsd.TrcSrcSingle {
		routeID = 0
	}
	if routeID >= 0x80 {
		return ocsd.ErrInvalidID
	}

	if _, exists := dt.decodeElements[routeID]; exists {
		return ocsd.ErrAttachTooMany
	}
	if pktIn == nil && iter == nil {
		return ocsd.ErrNotInit
	}

	// No decoder manager is needed for direct injection.
	elem := NewDecodeTreeElement(name, flagApplier, wiring, pktIn, iter, true)
	elem.Protocol = protocol

	dt.decodeElements[routeID] = elem
	if dt.frameDeformatter != nil && pktIn != nil {
		dt.frameDeformatter.SetIDStream(routeID, pktIn)
	}
	dt.attachElementDependencies(elem)

	return nil
}

func (dt *DecodeTree) attachElementDependencies(elem *DecodeTreeElement) {
	if elem == nil || elem.PipelineWiring == nil || dt.genElemOut == nil {
		return
	}
	dt.wireTraceElemOut(elem, dt.genElemOut)
}

func (dt *DecodeTree) drainPullIteratorsToSink() error {
	if dt.genElemOut == nil {
		return nil
	}

	for {
		progressed := false
		for _, csID := range dt.sortedElementIDs() {
			elem := dt.decodeElements[csID]
			if elem == nil || elem.Iterator == nil {
				continue
			}

			trcElem, err := elem.Iterator.Next()
			if errors.Is(err, io.EOF) {
				continue
			}
			if err != nil {
				return err
			}
			if trcElem == nil {
				continue
			}

			if err := dt.genElemOut.TraceElemIn(trcElem.Index, trcElem.TraceID, trcElem); err != nil {
				return err
			}
			progressed = true
		}
		if !progressed {
			return nil
		}
	}
}

func (dt *DecodeTree) wireTraceElemOut(elem *DecodeTreeElement, outI ocsd.GenElemProcessor) {
	if elem == nil || outI == nil {
		return
	}
	if elem.PipelineWiring != nil {
		elem.PipelineWiring(outI)
	}
}

func (dt *DecodeTree) nextFromElement(elem *DecodeTreeElement) (*ocsd.TraceElement, error) {
	if elem == nil {
		return nil, io.EOF
	}
	if elem.Iterator != nil {
		return elem.Iterator.Next()
	}
	if elem.PushAdapter == nil && elem.PipelineWiring != nil {
		elem.PushAdapter = common.NewPushToPullAdapter()
		if dt.genElemOut != nil {
			dt.wireTraceElemOut(elem, &teeGenElemOut{primary: dt.genElemOut, secondary: elem.PushAdapter})
		} else {
			dt.wireTraceElemOut(elem, elem.PushAdapter)
		}
	}
	if elem.PushAdapter != nil {
		trcElem, err := elem.PushAdapter.Next()
		if err != nil {
			return nil, err
		}
		elem.PushAdapter.Ack()
		return trcElem, nil
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
	if elem := dt.decodeElements[routeID]; elem != nil && elem.PushAdapter != nil {
		elem.PushAdapter.Close()
	}
	delete(dt.decodeElements, routeID)
}

// SetGenTraceElemOutI attaches a sink for generic trace element outputs generated by the entire tree.
func (dt *DecodeTree) SetGenTraceElemOutI(outI ocsd.GenElemProcessor) {
	dt.genElemOut = outI
	for _, elem := range dt.decodeElements {
		if elem != nil && elem.PushAdapter != nil {
			dt.wireTraceElemOut(elem, &teeGenElemOut{primary: outI, secondary: elem.PushAdapter})
			continue
		}
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
