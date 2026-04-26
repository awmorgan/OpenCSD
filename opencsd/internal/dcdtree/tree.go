package dcdtree

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"

	"opencsd/internal/common"
	"opencsd/internal/demux"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
)

const (
	maxTraceRouteID = 0x80
	writeChunkSize  = 64 * 1024
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
// and read from during Write. Concurrent configuration and data processing
// will result in a runtime panic.
type DecodeTree struct {
	treeType         ocsd.DcdTreeSrc
	frameDeformatter *demux.FrameDeformatter
	decodeElements   map[uint8]*DecodeTreeElement

	defaultMapper memacc.Mapper
	createdMapper bool

	decoderRoot ocsd.TraceDecoder

	// ...existing code...
}

type traceDataReaderSetter interface {
	SetReader(io.Reader)
}

func (dt *DecodeTree) CanAttachReader() bool {
	_, ok := dt.readerSetter()
	return ok
}

func (dt *DecodeTree) readerSetter() (traceDataReaderSetter, bool) {
	if dt == nil || dt.frameDeformatter != nil || dt.treeType != ocsd.TrcSrcSingle {
		return nil, false
	}

	elem := dt.decodeElements[0]
	if elem == nil {
		return nil, false
	}

	setter, ok := elem.DataIn.(traceDataReaderSetter)
	return setter, ok
}

// ...existing code...

func (dt *DecodeTree) AttachReader(r io.Reader) error {
	if dt == nil {
		return ocsd.ErrNotInit
	}
	if r == nil {
		return ocsd.ErrInvalidParamVal
	}

	setter, ok := dt.readerSetter()
	if !ok {
		return ocsd.ErrInvalidParamVal
	}

	setter.SetReader(r)
	return nil
}

// NewDecodeTree creates a new Trace Decode Tree using the supplied decoder registry.
// A non-nil registry is required.
func NewDecodeTree(srcType ocsd.DcdTreeSrc, formatterCfgFlags uint32) (*DecodeTree, error) {
	dt := &DecodeTree{
		treeType:       srcType,
		decodeElements: make(map[uint8]*DecodeTreeElement),
	}

	if srcType != ocsd.TrcSrcFrameFormatted {
		return dt, nil
	}

	dt.frameDeformatter = demux.NewFrameDeformatter()
	if err := dt.frameDeformatter.Configure(formatterCfgFlags); err != nil {
		return nil, fmt.Errorf("%w: configure frame deformatter: %w", ErrCreateDecodeTree, err)
	}
	dt.decoderRoot = dt.frameDeformatter

	return dt, nil
}

// Destroy cleans up memory accessors (although GC does mostly).
func (dt *DecodeTree) Destroy() {
	dt.decodeElements = nil
	dt.frameDeformatter = nil
	if dt.createdMapper {
		dt.defaultMapper = nil
	}
}

// Write handles incoming raw byte trace streams into the tree.
func (dt *DecodeTree) Write(index ocsd.TrcIndex, data []byte) (uint32, error) {
	return dt.WriteContext(context.Background(), index, data)
}

// WriteContext handles incoming raw byte trace streams into the tree with cancellation support.
func (dt *DecodeTree) WriteContext(ctx context.Context, index ocsd.TrcIndex, data []byte) (uint32, error) {
	if err := contextErr(ctx); err != nil {
		return 0, err
	}

	proc := dt.writeTarget()
	if proc == nil {
		return 0, ocsd.ErrNotInit
	}

	return writeDecoderContext(ctx, proc, index, data)
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (dt *DecodeTree) writeTarget() ocsd.TraceDecoder {
	if dt.decoderRoot != nil {
		return dt.decoderRoot
	}
	if dt.treeType != ocsd.TrcSrcSingle {
		return nil
	}

	elem := dt.decodeElements[0]
	if elem == nil {
		return nil
	}
	return elem.DataIn
}

func writeDecoderContext(ctx context.Context, proc ocsd.TraceDecoder, index ocsd.TrcIndex, data []byte) (uint32, error) {
	if ctx == nil || len(data) <= writeChunkSize {
		return proc.Write(index, data)
	}

	var total uint32
	for offset := 0; offset < len(data); {
		if err := contextErr(ctx); err != nil {
			return total, err
		}

		end := min(offset+writeChunkSize, len(data))
		amt, err := proc.Write(index+ocsd.TrcIndex(offset), data[offset:end])
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

// Flush forwards flush control directly to the decoder root.
func (dt *DecodeTree) Flush() error {
	return dt.routeControl(func(dec ocsd.TraceDecoder) error {
		return dec.Flush()
	})
}

// Reset forwards reset control directly to the decoder root.
func (dt *DecodeTree) Reset(index ocsd.TrcIndex) error {
	return dt.routeControl(func(dec ocsd.TraceDecoder) error {
		return dec.Reset(index)
	})
}

// Close forwards end-of-trace control directly to the decoder root.
func (dt *DecodeTree) Close() error {
	return dt.routeControl(func(dec ocsd.TraceDecoder) error {
		return dec.Close()
	})
}

// AddPullDecoder registers decoder input routing and pull-based output iteration into the tree.
func (dt *DecodeTree) AddPullDecoder(routeID uint8, name string, protocol ocsd.TraceProtocol, pktIn ocsd.TraceDecoder, iter ocsd.TraceIterator, flagApplier common.FlagApplier) error {
	routeID = dt.normalizedRouteID(routeID)
	if err := validatePullDecoder(routeID, pktIn, iter); err != nil {
		return err
	}

	controlIn, _ := iter.(ocsd.TraceDecoder)
	elem, exists := dt.decodeElements[routeID]
	if !exists {
		// No decoder manager is needed for direct injection.
		elem = NewDecodeTreeElement(name, flagApplier, pktIn, controlIn, iter, true)
		elem.Protocol = protocol
		dt.decodeElements[routeID] = elem
	} else if err := elem.attach(name, protocol, pktIn, controlIn, iter, flagApplier); err != nil {
		return err
	}

	if pktIn != nil {
		dt.setIDStream(routeID, pktIn)
	}
	return nil
}

func validatePullDecoder(routeID uint8, pktIn ocsd.TraceDecoder, iter ocsd.TraceIterator) error {
	if routeID >= maxTraceRouteID {
		return ocsd.ErrInvalidID
	}
	if pktIn == nil && iter == nil {
		return ocsd.ErrNotInit
	}
	return nil
}

func (dt *DecodeTree) normalizedRouteID(routeID uint8) uint8 {
	if dt.treeType == ocsd.TrcSrcSingle {
		return 0
	}
	return routeID
}

func (dt *DecodeTree) setIDStream(routeID uint8, dec ocsd.TraceDecoder) {
	if dt.frameDeformatter != nil {
		dt.frameDeformatter.SetIDStream(routeID, dec)
	}
}

func (dt *DecodeTree) nextFromElement(elem *DecodeTreeElement) (*ocsd.TraceElement, error) {
	if elem == nil || elem.Iterator == nil {
		return nil, io.EOF
	}
	return elem.Iterator.Next()
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

	sawWait := false
	for _, csID := range ids {
		trcElem, err := dt.nextFromElement(dt.decodeElements[csID])
		if errors.Is(err, io.EOF) {
			continue
		}
		if errors.Is(err, ocsd.ErrWait) {
			sawWait = true
			continue
		}
		if err != nil {
			return nil, err
		}
		if trcElem != nil {
			return trcElem, nil
		}
	}
	if sawWait {
		return nil, ocsd.ErrWait
	}
	return nil, io.EOF
}

// RemoveDecoder removes a decoder mapped to the given CSID.
func (dt *DecodeTree) RemoveDecoder(csID uint8) {
	routeID := dt.normalizedRouteID(csID)
	dt.setIDStream(routeID, nil)
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
		fn(csID, dt.decodeElements[csID])
	}
}

// Elements provides a standard Go 1.23 iterator over the trace elements.
// It wraps the legacy pull-based Next() method.
func (dt *DecodeTree) Elements() iter.Seq2[*ocsd.TraceElement, error] {
	return ocsd.GenerateElements(dt.Next)
}

func (dt *DecodeTree) sortedElementIDs() []uint8 {
	ids := make([]uint8, 0, len(dt.decodeElements))
	for id := range dt.decodeElements {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (dt *DecodeTree) routeControl(dispatch func(dec ocsd.TraceDecoder) error) error {
	targets := dt.controlTargets()
	if len(targets) == 0 {
		return ocsd.ErrNotInit
	}

	var outErr error
	for _, target := range targets {
		if err := dispatch(target); err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

func (dt *DecodeTree) controlTargets() []ocsd.TraceDecoder {
	targets := make([]ocsd.TraceDecoder, 0, len(dt.decodeElements)+1)
	if dt.decoderRoot != nil {
		targets = append(targets, dt.decoderRoot)
	}

	for _, routeID := range dt.sortedElementIDs() {
		elem := dt.decodeElements[routeID]
		if elem == nil {
			continue
		}
		if dt.decoderRoot == nil && elem.DataIn != nil {
			targets = append(targets, elem.DataIn)
		}
		if elem.ControlIn != nil {
			targets = append(targets, elem.ControlIn)
		}
	}
	return targets
}
