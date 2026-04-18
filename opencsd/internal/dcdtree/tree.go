package dcdtree

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
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
	if dt == nil {
		return false
	}
	if dt.frameDeformatter != nil {
		return false
	}
	if dt.treeType != ocsd.TrcSrcSingle {
		return false
	}

	elem := dt.decodeElements[0]
	if elem == nil || elem.DataIn == nil {
		return false
	}

	_, ok := elem.DataIn.(traceDataReaderSetter)
	return ok
}

// ...existing code...

func (dt *DecodeTree) AttachReader(r io.Reader) error {
	if dt == nil {
		return ocsd.ErrNotInit
	}
	if r == nil {
		return ocsd.ErrInvalidParamVal
	}
	if !dt.CanAttachReader() {
		return ocsd.ErrInvalidParamVal
	}

	elem := dt.decodeElements[0]
	setter := elem.DataIn.(traceDataReaderSetter)
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

// Write handles incoming raw byte trace streams into the tree.
func (dt *DecodeTree) Write(index ocsd.TrcIndex, data []byte) (uint32, error) {
	return dt.WriteContext(context.Background(), index, data)
}

// WriteContext handles incoming raw byte trace streams into the tree with cancellation support.
func (dt *DecodeTree) WriteContext(ctx context.Context, index ocsd.TrcIndex, data []byte) (uint32, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
	}

	const processChunk = 64 * 1024

	processWithContext := func(proc ocsd.TraceDecoder) (uint32, error) {
		if proc == nil {
			return 0, ocsd.ErrNotInit
		}
		if ctx == nil || len(data) <= processChunk {
			return proc.Write(index, data)
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
			amt, err := proc.Write(chunkIdx, data[offset:end])
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
	if dt.treeType == ocsd.TrcSrcSingle {
		routeID = 0
	}
	if routeID >= 0x80 {
		return ocsd.ErrInvalidID
	}
	if pktIn == nil && iter == nil {
		return ocsd.ErrNotInit
	}

	controlIn, ok := iter.(ocsd.TraceDecoder)
	if !ok {
		controlIn = nil
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
		if controlIn != nil {
			elem.ControlIn = controlIn
		}
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
	elem := NewDecodeTreeElement(name, flagApplier, pktIn, controlIn, iter, true)
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
		trcElem, err := elem.Iterator.Next()
		return trcElem, err
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
	sawWait := false
	for _, csID := range ids {
		elem := dt.decodeElements[csID]
		if elem == nil || elem.Iterator == nil {
			continue
		}
		trcElem, err := elem.Iterator.Next()
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

// Elements provides a standard Go 1.23 iterator over the trace elements.
// It wraps the legacy pull-based Next() method.
func (dt *DecodeTree) Elements() iter.Seq2[*ocsd.TraceElement, error] {
	return func(yield func(*ocsd.TraceElement, error) bool) {
		for {
			elem, err := dt.Next()
			if err != nil {
				// Don't yield EOF as an error, it just means iteration is done
				if !errors.Is(err, io.EOF) {
					yield(nil, err)
				}
				return
			}
			// Yield the element. If the consumer breaks the loop, yield returns false
			if !yield(elem, nil) {
				return
			}
		}
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

func (dt *DecodeTree) routeControl(dispatch func(dec ocsd.TraceDecoder) error) error {
	hadTarget := false
	var outErr error

	if dt.decoderRoot != nil {
		hadTarget = true
		if err := dispatch(dt.decoderRoot); err != nil && outErr == nil {
			outErr = err
		}
	}

	for _, routeID := range dt.sortedElementIDs() {
		elem := dt.decodeElements[routeID]
		if elem == nil {
			continue
		}

		if dt.decoderRoot == nil && elem.DataIn != nil {
			hadTarget = true
			if err := dispatch(elem.DataIn); err != nil && outErr == nil {
				outErr = err
			}
		}

		if elem.ControlIn != nil {
			hadTarget = true
			if err := dispatch(elem.ControlIn); err != nil && outErr == nil {
				outErr = err
			}
		}
	}

	if !hadTarget {
		return ocsd.ErrNotInit
	}
	return outErr
}
