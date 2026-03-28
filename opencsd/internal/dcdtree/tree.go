package dcdtree

import (
	"context"
	"errors"
	"fmt"
	"opencsd/internal/common"
	"opencsd/internal/demux"
	"opencsd/internal/idec"

	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
	"slices"
)

var (
	// ErrCreateFullDecoder indicates full decoder creation failed.
	ErrCreateFullDecoder = errors.New("create full decoder failed")
	// ErrCreatePacketProcessor indicates packet processor creation failed.
	ErrCreatePacketProcessor = errors.New("create packet processor failed")
)

// DecodeTree manages the decoding of trace data from a single trace sink.
//
// IMPORTANT: DecodeTree is strictly thread-unsafe. The underlying elements map
// (decodeElements) is written to during CreateFullDecoder/RemoveDecoder
// and read from during TraceDataIn. Concurrent configuration and data processing
// will result in a runtime panic.
type DecodeTree struct {
	registry         *DecoderRegister
	treeType         ocsd.DcdTreeSrc
	frameDeformatter *demux.FrameDeformatter
	decodeElements   map[uint8]*DecodeTreeElement

	defaultMapper memacc.Mapper
	createdMapper bool

	decoderRoot ocsd.TrcDataProcessor
	instrDecode common.InstrDecode
	memAccess   common.TargetMemAccess
	genElemOut  ocsd.GenElemProcessor
}

type traceIDConfig interface {
	TraceID() uint8
}

// NewDecodeTree creates a new Trace Decode Tree using the supplied decoder registry.
// A non-nil registry is required.
func NewDecodeTree(srcType ocsd.DcdTreeSrc, formatterCfgFlags uint32, registry *DecoderRegister) *DecodeTree {
	if registry == nil {
		return nil
	}

	dt := &DecodeTree{
		registry:       registry,
		treeType:       srcType,
		decodeElements: make(map[uint8]*DecodeTreeElement),
		instrDecode:    idec.NewDecoder(),
	}

	if srcType == ocsd.TrcSrcFrameFormatted {
		dt.frameDeformatter = demux.NewFrameDeformatter()
		dt.frameDeformatter.Configure(formatterCfgFlags)
		dt.decoderRoot = dt.frameDeformatter
	}

	return dt
}

// NewDefaultDecodeTree creates a new Trace Decode Tree using a fresh built-in registry.
func NewDefaultDecodeTree(srcType ocsd.DcdTreeSrc, formatterCfgFlags uint32) *DecodeTree {
	return NewDecodeTree(srcType, formatterCfgFlags, NewBuiltinDecoderRegister())
}

// CreateDecodeTree creates a new Trace Decode Tree using the package default registry.
// Deprecated: prefer NewDefaultDecodeTree.
func CreateDecodeTree(srcType ocsd.DcdTreeSrc, formatterCfgFlags uint32) *DecodeTree {
	return NewDefaultDecodeTree(srcType, formatterCfgFlags)
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

	if dt.decoderRoot != nil {
		amt, resp, err := dt.decoderRoot.TraceDataIn(op, index, data)
		return amt, resp, err
	}

	// Unformatted single trace source fallback
	if dt.treeType == ocsd.TrcSrcSingle {
		elem := dt.decodeElements[0]
		if elem != nil && elem.DataIn != nil {
			amt, resp, err := elem.DataIn.TraceDataIn(op, index, data)
			return amt, resp, err
		}
	}
	return 0, ocsd.RespFatalNotInit, nil
}

// CreateFullDecoder creates a full decoder within the tree for a generic trace config.
func (dt *DecodeTree) CreateFullDecoder(decoderName string, config any) error {
	err := dt.createDecoder(decoderName, config, true)
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %q (%w)", ErrCreateFullDecoder, decoderName, err)
}

// CreatePacketProcessor creates a packet processor within the tree for a generic trace config.
func (dt *DecodeTree) CreatePacketProcessor(decoderName string, config any) error {
	err := dt.createDecoder(decoderName, config, false)
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %q (%w)", ErrCreatePacketProcessor, decoderName, err)
}

func (dt *DecodeTree) createDecoder(decoderName string, config any, fullDecoder bool) error {
	registry := dt.registry
	if registry == nil {
		return ocsd.ErrNotInit
	}

	manager, err := registry.DecoderManagerByName(decoderName)
	if err != nil {
		return err
	}

	routeID, err := dt.routeIDFromConfig(config)
	if err != nil {
		return err
	}

	if _, exists := dt.decodeElements[routeID]; exists {
		return ocsd.ErrAttachTooMany
	}

	var pktIn ocsd.TrcDataProcessor
	var handle any

	if fullDecoder {
		var err2 error
		pktIn, handle, err2 = manager.CreateDecoder(int(routeID), config)
		if err2 != nil {
			return err2
		}
	} else {
		var err2 error
		pktIn, handle, err2 = manager.CreatePacketProcessor(int(routeID), config)
		if err2 != nil {
			return err2
		}
	}

	if handle == nil {
		return ocsd.ErrFail
	}

	elem := NewDecodeTreeElement(decoderName, manager, handle, pktIn, true)
	dt.decodeElements[routeID] = elem

	if dt.frameDeformatter != nil && pktIn != nil {
		dt.frameDeformatter.SetIDStream(routeID, pktIn)
	}
	dt.attachElementDependencies(elem)

	return nil
}

func (dt *DecodeTree) routeIDFromConfig(config any) (uint8, error) {
	cfg, ok := config.(traceIDConfig)
	if !ok {
		return 0, ocsd.ErrInvalidParamType
	}

	routeID := cfg.TraceID()
	if dt.treeType == ocsd.TrcSrcSingle {
		routeID = 0
	}
	if routeID >= 0x80 {
		return 0, ocsd.ErrInvalidID
	}
	return routeID, nil
}

func (dt *DecodeTree) attachElementDependencies(elem *DecodeTreeElement) {
	if dt.genElemOut != nil {
		if elem.SetTraceElemOut != nil {
			elem.SetTraceElemOut(dt.genElemOut)
		}
	}
	if dt.instrDecode != nil {
		if elem.SetInstrDecode != nil {
			elem.SetInstrDecode(dt.instrDecode)
		}
	}
	if dt.memAccess != nil {
		if elem.SetMemAccess != nil {
			elem.SetMemAccess(dt.memAccess)
		}
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
		if elem.SetTraceElemOut != nil {
			elem.SetTraceElemOut(outI)
		}
	}
}

// SetInstrDecoder attaches the instruction decoder for code-following decoders in the tree.
func (dt *DecodeTree) SetInstrDecoder(instrDec common.InstrDecode) {
	dt.instrDecode = instrDec
	for _, elem := range dt.decodeElements {
		if elem.SetInstrDecode != nil {
			elem.SetInstrDecode(instrDec)
		}
	}
}

// SetMemAccessI attaches the memory accessor interface for instruction decoding.
func (dt *DecodeTree) SetMemAccessI(memI common.TargetMemAccess) {
	dt.memAccess = memI
	for _, elem := range dt.decodeElements {
		if elem.SetMemAccess != nil {
			elem.SetMemAccess(memI)
		}
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
