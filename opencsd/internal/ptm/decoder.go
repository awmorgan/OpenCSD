package ptm

import (
	"errors"
	"fmt"
	"io"

	"opencsd/internal/common"
	"opencsd/internal/idec"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
)

type traceElemEvent struct {
	index   ocsd.TrcIndex
	traceID uint8
	elem    ocsd.TraceElement
}

type decodeState int

const (
	decodeNoSync decodeState = iota
	decodeWaitSync
	decodeWaitISync
	decodePkts
	decodeContISync
	decodeContAtom
	decodeContWPUp
	decodeContBranch
)

type waypointTraceOp int

const (
	traceWaypoint waypointTraceOp = iota
	traceToAddrExcl
	traceToAddrIncl
)

type peAddrState struct {
	isa       ocsd.ISA
	instrAddr ocsd.VAddr
	valid     bool
}

type PtmAtoms struct {
	atom      ocsd.PktAtom
	rootIndex ocsd.TrcIndex
}

func (a *PtmAtoms) set(atom ocsd.PktAtom, rootIndex ocsd.TrcIndex) {
	a.atom = atom
	a.rootIndex = rootIndex
}

func (a *PtmAtoms) getCurrAtomVal() ocsd.AtmVal {
	if (a.atom.EnBits & 0x1) != 0 {
		return ocsd.AtomE
	}
	return ocsd.AtomN
}

func (a *PtmAtoms) numAtoms() int {
	return int(a.atom.Num)
}

func (a *PtmAtoms) pktIndex() ocsd.TrcIndex {
	return a.rootIndex
}

func (a *PtmAtoms) clearAtom() {
	if a.atom.Num > 0 {
		a.atom.Num--
		a.atom.EnBits >>= 1
	}
}

func (a *PtmAtoms) clearAll() {
	a.atom.Num = 0
}

type PktDecode struct {
	Name         string
	traceElemOut ocsd.GenElemProcessor
	MemAccess    common.TargetMemAccess
	InstrDecode  common.InstrDecode
	IndexCurrPkt ocsd.TrcIndex
	Config       *Config
	CurrPacketIn *Packet

	currState   decodeState
	unsyncInfo  ocsd.UnsyncInfo
	peContext   ocsd.PEContext
	currPeState peAddrState
	needIsync   bool

	csID           uint8
	instrInfo      ocsd.InstrInfo
	memNaccPending bool
	naccAddr       ocsd.VAddr
	iSyncPeCtxt    bool

	atoms       PtmAtoms
	returnStack common.AddrReturnStack
	outputElem  ocsd.TraceElement

	// Pull-iterator fields
	pendingElements []traceElemEvent
	collectElements bool
}

func (d *PktDecode) ApplyFlags(flags uint32) error { return nil }

func NewPktDecode(cfg *Config) (*PktDecode, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: PTM config cannot be nil", ocsd.ErrInvalidParamVal)
	}

	instIDNum := int(cfg.TraceID())
	d := &PktDecode{
		Name: fmt.Sprintf("DCD_PTM_%d", instIDNum),
	}
	d.configureDecoder()
	if err := d.SetProtocolConfig(cfg); err != nil {
		return nil, err
	}
	return d, nil
}

// OutputTraceElement sends an element using IndexCurrPkt (or queues if in collect mode).
func (d *PktDecode) OutputTraceElement(traceID uint8, elem *ocsd.TraceElement) error {
	if d.collectElements {
		e := traceElemEvent{d.IndexCurrPkt, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	if d.traceElemOut == nil {
		e := traceElemEvent{d.IndexCurrPkt, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	err := d.traceElemOut.TraceElemIn(d.IndexCurrPkt, traceID, elem)
	if ocsd.IsDataContErr(err) {
		return nil
	}
	if ocsd.IsDataWaitErr(err) {
		return ocsd.ErrWait
	}
	return err
}

// NextElement returns the next queued trace element or EOF if none available.
func (d *PktDecode) NextElement() (ocsd.TrcIndex, uint8, ocsd.TraceElement, error) {
	if len(d.pendingElements) == 0 {
		return 0, 0, ocsd.TraceElement{}, io.EOF
	}
	e := d.pendingElements[0]
	d.pendingElements = d.pendingElements[1:]
	if d.traceElemOut != nil {
		err := d.traceElemOut.TraceElemIn(e.index, e.traceID, &e.elem)
		if ocsd.IsDataContErr(err) {
			return e.index, e.traceID, e.elem, nil
		}
		if ocsd.IsDataWaitErr(err) {
			d.putBackElement(e.index, e.traceID, e.elem)
			return 0, 0, ocsd.TraceElement{}, ocsd.ErrWait
		}
		if err != nil {
			return 0, 0, ocsd.TraceElement{}, err
		}
	}
	return e.index, e.traceID, e.elem, nil
}

// putBackElement unreads an element to the front of the pending queue.
func (d *PktDecode) putBackElement(index ocsd.TrcIndex, traceID uint8, elem ocsd.TraceElement) {
	e := traceElemEvent{index, traceID, elem}
	d.pendingElements = append([]traceElemEvent{e}, d.pendingElements...)
}

func (d *PktDecode) SetTraceElemOut(out ocsd.GenElemProcessor) {
	d.traceElemOut = out
}

func cloneQueuedElem(elem *ocsd.TraceElement) ocsd.TraceElement {
	clone := *elem
	if elem.PtrExtendedData != nil {
		clone.PtrExtendedData = append([]byte(nil), elem.PtrExtendedData...)
	}
	return clone
}

// OutputTraceElementIdx sends an element at an explicit index (or queues if in collect mode).
func (d *PktDecode) OutputTraceElementIdx(idx ocsd.TrcIndex, traceID uint8, elem *ocsd.TraceElement) error {
	if d.collectElements {
		e := traceElemEvent{idx, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	if d.traceElemOut == nil {
		e := traceElemEvent{idx, traceID, cloneQueuedElem(elem)}
		d.pendingElements = append(d.pendingElements, e)
		return nil
	}
	err := d.traceElemOut.TraceElemIn(idx, traceID, elem)
	if ocsd.IsDataContErr(err) {
		return nil
	}
	if ocsd.IsDataWaitErr(err) {
		return ocsd.ErrWait
	}
	return err
}

// AccessMemory reads target memory.
func (d *PktDecode) AccessMemory(address ocsd.VAddr, traceID uint8, memSpace ocsd.MemSpaceAcc, reqBytes uint32) (uint32, []byte, error) {
	if d.MemAccess != nil {
		return d.MemAccess.ReadTargetMemory(address, traceID, memSpace, reqBytes)
	}
	return 0, nil, ocsd.ErrDcdInterfaceUnused
}

// InstrDecodeCall calls the attached instruction decoder.
func (d *PktDecode) InstrDecodeCall(instrInfo *ocsd.InstrInfo) error {
	if d.InstrDecode != nil {
		return d.InstrDecode.DecodeInstruction(instrInfo)
	}
	return ocsd.ErrDcdInterfaceUnused
}

// InvalidateMemAccCache invalidates the memory access cache.
func (d *PktDecode) InvalidateMemAccCache(traceID uint8) error {
	if d.MemAccess != nil {
		d.MemAccess.InvalidateMemAccCache(traceID)
		return nil
	}
	return ocsd.ErrDcdInterfaceUnused
}

// TracePacketData is the explicit packet data entrypoint used by split interfaces.
func (d *PktDecode) TracePacketData(indexSOP ocsd.TrcIndex, pktIn *Packet) error {
	if pktIn == nil {
		return ocsd.ErrInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = indexSOP
	d.collectElements = true
	err := d.ProcessPacket()
	d.collectElements = false
	// Drain queued elements only when using legacy push sink wiring.
	if err == nil && d.traceElemOut != nil {
		for {
			_, _, _, nextErr := d.NextElement()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				return nextErr
			}
		}
	}
	return err
}

// Next returns one decoded trace element at a time for pull-based consumers.
func (d *PktDecode) Next() (*ocsd.TraceElement, error) {
	idx, traceID, elem, err := d.NextElement()
	if err != nil {
		return nil, err
	}
	e := elem
	e.Index = idx
	e.TraceID = traceID
	return &e, nil
}

// TracePacketEOT forwards an EOT control operation through the legacy multiplexer.
func (d *PktDecode) TracePacketEOT() error {
	return d.OnEOT()
}

// TracePacketFlush forwards a flush control operation through the legacy multiplexer.
func (d *PktDecode) TracePacketFlush() error {
	return d.OnFlush()
}

// TracePacketReset forwards a reset control operation through the legacy multiplexer.
func (d *PktDecode) TracePacketReset(indexSOP ocsd.TrcIndex) error {
	_ = indexSOP
	d.OnReset()
	return nil
}

func (d *PktDecode) TraceID() uint8 {
	return d.csID
}

func (d *PktDecode) configureDecoder() {
	d.csID = 0
	d.instrInfo.PeType.Profile = ocsd.ProfileUnknown
	d.instrInfo.PeType.Arch = ocsd.ArchUnknown
	d.instrInfo.DsbDmbWaypoints = 0
	d.unsyncInfo = ocsd.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *PktDecode) processStateIsCont() bool {
	return d.currState >= decodeContISync
}

func (d *PktDecode) resetDecoder() {
	d.currState = decodeNoSync
	d.needIsync = true
	d.pendingElements = d.pendingElements[:0]

	d.instrInfo.ISA = ocsd.ISAUnknown
	d.memNaccPending = false

	d.peContext.CtxtIDValid = false
	d.peContext.Bits64 = false
	d.peContext.VMIDValid = false
	d.peContext.ExceptionLevel = ocsd.ELUnknown
	d.peContext.SecurityLevel = ocsd.SecSecure
	d.peContext.ELValid = false

	d.currPeState.instrAddr = 0
	d.currPeState.isa = ocsd.ISAUnknown
	d.currPeState.valid = false

	d.atoms.clearAll()
	d.outputElem.Init()
}

func (d *PktDecode) SetProtocolConfig(config *Config) error {
	d.Config = config
	if d.Config == nil {
		return ocsd.ErrNotInit
	}
	d.csID = d.Config.TraceID()

	if d.Config.HasRetStack() {
		d.returnStack.Active = d.Config.EnaRetStack()
	}

	d.instrInfo.PeType.Profile = d.Config.CoreProf
	d.instrInfo.PeType.Arch = d.Config.ArchVer
	if d.Config.DmsbWayPt() {
		d.instrInfo.DsbDmbWaypoints = 1
	} else {
		d.instrInfo.DsbDmbWaypoints = 0
	}
	d.instrInfo.WfiWfeBranch = 0
	d.instrInfo.ThumbItConditions = 0
	d.instrInfo.TrackItBlock = 0
	return nil
}

func (d *PktDecode) OnEOT() error {
	var err error

	for err == nil && (d.processStateIsCont() || d.memNaccPending || d.atoms.numAtoms() > 0) {
		if d.processStateIsCont() {
			err = d.contProcess()
			continue
		}

		if d.atoms.numAtoms() > 0 {
			if d.currPeState.valid {
				err = d.processAtom()
			} else {
				d.atoms.clearAll()
				// previously returned RespWarnCont. we'll just continue.
			}
			continue
		}

		d.checkPendingNacc(&err)
	}

	if err != nil {
		return err
	}

	d.outputElem.SetType(ocsd.GenElemEOTrace)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncEOT)
	return d.OutputTraceElement(d.csID, &d.outputElem)
}

func (d *PktDecode) OnReset() {
	d.unsyncInfo = ocsd.UnsyncResetDecoder
	d.resetDecoder()
}

func (d *PktDecode) OnFlush() error {
	return d.contProcess()
}

func (d *PktDecode) ProcessPacket() error {
	var err error
	for {
		var next decodeState
		var done bool
		switch d.currState {
		case decodeNoSync:
			next, err, done = d.handleNoSync()
		case decodeWaitSync:
			next, err, done = d.handleWaitSync()
		case decodeWaitISync:
			next, err, done = d.handleWaitISync()
		case decodePkts:
			next, err, done = decodePkts, d.decodePacket(), true
		default:
			return nil
		}
		d.currState = next
		if done {
			return err
		}
	}
}

func (d *PktDecode) handleNoSync() (decodeState, error, bool) {
	d.outputElem.SetType(ocsd.GenElemNoSync)
	d.outputElem.SetUnSyncEOTReason(ocsd.UnsyncInfo(d.unsyncInfo))
	err := d.OutputTraceElement(d.csID, &d.outputElem)
	if d.CurrPacketIn.Type == PktASync {
		return decodeWaitISync, err, true
	}
	return decodeWaitSync, err, true
}

func (d *PktDecode) handleWaitSync() (decodeState, error, bool) {
	if d.CurrPacketIn.Type == PktASync {
		return decodeWaitISync, nil, true
	}
	return decodeWaitSync, nil, true
}

func (d *PktDecode) handleWaitISync() (decodeState, error, bool) {
	if d.CurrPacketIn.Type == PktISync {
		return decodePkts, nil, false // continue to decodePkts
	}
	return decodeWaitISync, nil, true
}

func (d *PktDecode) contProcess() error {
	var err error

	switch d.currState {
	case decodeContISync:
		err = d.processIsync()
	case decodeContAtom:
		err = d.processAtom()
	case decodeContWPUp:
		err = d.processWPUpdate()
	case decodeContBranch:
		err = d.processBranch()
	}

	if err == nil && d.processStateIsCont() {
		d.currState = decodePkts
	}
	return err
}

func (d *PktDecode) decodePacket() error {
	var err error

	pkt := d.CurrPacketIn
	switch pkt.Type {
	case PktIncompleteEOT:
		return nil
	case PktBadSequence, PktReserved:
		d.currState = decodeWaitSync
		d.needIsync = true
		d.outputElem.SetType(ocsd.GenElemNoSync)
		return d.OutputTraceElement(d.csID, &d.outputElem)
	}

	switch pkt.Type {
	case PktNotSync:
		// ignore
	case PktASync, PktIgnore:
		// ignore
	case PktISync:
		err = d.processIsync()
	case PktBranchAddress:
		err = d.processBranch()
	case PktTrigger:
		d.outputElem.SetType(ocsd.GenElemEvent)
		d.outputElem.SetEvent(ocsd.EventTrigger, 0)
		err = d.OutputTraceElement(d.csID, &d.outputElem)
	case PktWPointUpdate:
		err = d.processWPUpdate()
	case PktContextID:
		update := true
		if d.peContext.CtxtIDValid && d.peContext.ContextID == pkt.Context.CtxtID {
			update = false
		}
		if update {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.CtxtIDValid = true
			d.outputElem.SetType(ocsd.GenElemPeContext)
			d.outputElem.SetContext(d.peContext)
			err = d.OutputTraceElement(d.csID, &d.outputElem)
		}
	case PktVMID:
		update := true
		if d.peContext.VMIDValid && d.peContext.VMID == uint32(pkt.Context.VMID) {
			update = false
		}
		if update {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.VMIDValid = true
			d.outputElem.SetType(ocsd.GenElemPeContext)
			d.outputElem.SetContext(d.peContext)
			err = d.OutputTraceElement(d.csID, &d.outputElem)
		}
	case PktAtom:
		if d.currPeState.valid {
			d.atoms.set(pkt.Atom, d.IndexCurrPkt)
			err = d.processAtom()
		} else {
			// warning, ignored
		}
	case PktTimestamp:
		d.outputElem.SetType(ocsd.GenElemTimestamp)
		d.outputElem.Timestamp = pkt.Timestamp
		if pkt.CCValid {
			d.outputElem.SetCycleCount(pkt.CycleCount)
		}
		err = d.OutputTraceElement(d.csID, &d.outputElem)
	case PktExceptionRet:
		d.outputElem.SetType(ocsd.GenElemExceptionRet)
		err = d.OutputTraceElement(d.csID, &d.outputElem)
	}
	return err
}

func (d *PktDecode) processIsync() error {
	var err error

	pkt := d.CurrPacketIn

	if d.currState == decodePkts {
		d.currPeState.instrAddr = pkt.AddrVal
		d.currPeState.isa = pkt.CurrISA
		d.currPeState.valid = true

		d.iSyncPeCtxt = pkt.CurrISA != pkt.PrevISA
		if pkt.Context.UpdatedC {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.CtxtIDValid = true
			d.iSyncPeCtxt = true
		}

		if pkt.Context.UpdatedV {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.VMIDValid = true
			d.iSyncPeCtxt = true
		}
		if pkt.Context.CurrNS {
			d.peContext.SecurityLevel = ocsd.SecNonsecure
		} else {
			d.peContext.SecurityLevel = ocsd.SecSecure
		}

		if d.needIsync || pkt.ISyncReason != ocsd.ISyncPeriodic {
			d.outputElem.SetType(ocsd.GenElemTraceOn)
			d.outputElem.SetTraceOnReason(ocsd.TraceOnNormal)
			switch pkt.ISyncReason {
			case ocsd.ISyncTraceRestartAfterOverflow:
				d.outputElem.SetTraceOnReason(ocsd.TraceOnOverflow)
			case ocsd.ISyncDebugExit:
				d.outputElem.SetTraceOnReason(ocsd.TraceOnExDebug)
			}
			if pkt.CCValid {
				d.outputElem.SetCycleCount(pkt.CycleCount)
			}
			err = d.OutputTraceElement(d.csID, &d.outputElem)
		} else {
			d.iSyncPeCtxt = false
		}
		d.needIsync = false
		d.returnStack.Flush()
	}

	if d.iSyncPeCtxt && err == nil {
		d.outputElem.SetType(ocsd.GenElemPeContext)
		d.outputElem.SetContext(d.peContext)
		d.outputElem.SetISA(d.currPeState.isa)
		err = d.OutputTraceElement(d.csID, &d.outputElem)
		d.iSyncPeCtxt = false
	}

	if errors.Is(err, ocsd.ErrWait) && d.iSyncPeCtxt {
		d.currState = decodeContISync
	}

	return err
}

func (d *PktDecode) processBranch() error {
	var err error

	pkt := d.CurrPacketIn

	if d.currState == decodePkts {
		if pkt.Exception.Present {
			d.outputElem.SetType(ocsd.GenElemException)
			d.outputElem.SetExceptionNum(uint32(pkt.Exception.Number))
			d.outputElem.ExceptionRetAddr = false
			if d.currPeState.valid {
				d.outputElem.ExceptionRetAddr = true
				d.outputElem.EndAddr = d.currPeState.instrAddr
			}
			if pkt.CCValid {
				d.outputElem.SetCycleCount(pkt.CycleCount)
			}
			err = d.OutputTraceElement(d.csID, &d.outputElem)
		} else {
			if d.currPeState.valid {
				err = d.processAtomRange(ocsd.AtomE, traceWaypoint, 0)
			}
		}

		d.currPeState.isa = pkt.CurrISA
		d.currPeState.instrAddr = pkt.AddrVal
		d.currPeState.valid = true
	}

	d.checkPendingNacc(&err)

	if errors.Is(err, ocsd.ErrWait) && d.memNaccPending {
		d.currState = decodeContBranch
	}
	return err
}

func (d *PktDecode) processWPUpdate() error {
	var err error

	if d.currPeState.valid {
		err = d.processAtomRange(ocsd.AtomE, traceToAddrIncl, d.CurrPacketIn.AddrVal)
	}

	d.checkPendingNacc(&err)

	if errors.Is(err, ocsd.ErrWait) && d.memNaccPending {
		d.currState = decodeContWPUp
	}
	return err
}

func (d *PktDecode) processAtom() error {
	var err error

	for d.atoms.numAtoms() > 0 && d.currPeState.valid && err == nil {
		err = d.processAtomRange(d.atoms.getCurrAtomVal(), traceWaypoint, 0)
		if !d.currPeState.valid {
			d.atoms.clearAll()
		} else {
			d.atoms.clearAtom()
		}
	}

	d.checkPendingNacc(&err)

	if errors.Is(err, ocsd.ErrWait) && (d.memNaccPending || d.atoms.numAtoms() > 0) {
		d.currState = decodeContAtom
	}

	return err
}

func (d *PktDecode) checkPendingNacc(errptr *error) {
	if d.memNaccPending && *errptr == nil {
		d.outputElem.SetType(ocsd.GenElemAddrNacc)
		d.outputElem.StartAddr = d.naccAddr
		if d.peContext.SecurityLevel == ocsd.SecSecure {
			d.outputElem.SetExceptionNum(uint32(ocsd.MemSpaceS))
		} else {
			d.outputElem.SetExceptionNum(uint32(ocsd.MemSpaceN))
		}
		*errptr = d.OutputTraceElementIdx(d.IndexCurrPkt, d.csID, &d.outputElem)
		d.memNaccPending = false
	}
}

func (d *PktDecode) processAtomRange(A ocsd.AtmVal, traceWPOp waypointTraceOp, nextAddrMatch ocsd.VAddr) error {
	var respErr error

	wpFound := false
	var err error

	d.instrInfo.InstrAddr = d.currPeState.instrAddr
	d.instrInfo.ISA = d.currPeState.isa

	d.outputElem.SetType(ocsd.GenElemInstrRange)

	wpFound, err = d.traceInstrToWP(traceWPOp, nextAddrMatch)
	if err != nil {
		if errors.Is(err, ocsd.ErrUnsupportedISA) {
			d.currPeState.valid = false
			return nil // Warning
		}
		return err
	}

	if wpFound {
		nextAddr := d.instrInfo.InstrAddr

		switch d.instrInfo.Type {
		case ocsd.InstrBr:
			if A == ocsd.AtomE {
				d.instrInfo.InstrAddr = d.instrInfo.BranchAddr
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.ISA)
				}
			}
		case ocsd.InstrBrIndirect:
			if A == ocsd.AtomE {
				d.currPeState.valid = false
				if d.returnStack.Active && d.CurrPacketIn.Type == PktAtom && (d.instrInfo.Subtype == ocsd.SInstrV8Ret || d.instrInfo.Subtype == ocsd.SInstrV7ImpliedRet) {
					popAddr, nextIsa, ok := d.returnStack.Pop()
					if !ok {
						return ocsd.ErrInvalidParamVal // Fatal
					} else {
						d.instrInfo.InstrAddr = popAddr
						d.instrInfo.NextISA = nextIsa
						d.currPeState.valid = true
					}
				}
				if d.instrInfo.IsLink != 0 {
					d.returnStack.Push(nextAddr, d.instrInfo.ISA)
				}
			}
		}

		d.outputElem.SetLastInstrInfo(A == ocsd.AtomE, d.instrInfo.Type, d.instrInfo.Subtype, d.instrInfo.InstrSize)
		d.outputElem.SetISA(d.currPeState.isa)
		if d.CurrPacketIn.CCValid {
			d.outputElem.SetCycleCount(d.CurrPacketIn.CycleCount)
		}
		d.outputElem.LastInstrCond = d.instrInfo.IsConditional != 0
		respErr = d.OutputTraceElementIdx(d.IndexCurrPkt, d.csID, &d.outputElem)

		d.currPeState.instrAddr = d.instrInfo.InstrAddr
		d.currPeState.isa = d.instrInfo.NextISA
	} else {
		d.currPeState.valid = false
		if d.outputElem.StartAddr != d.outputElem.EndAddr {
			d.outputElem.SetLastInstrInfo(true, d.instrInfo.Type, d.instrInfo.Subtype, d.instrInfo.InstrSize)
			d.outputElem.SetISA(d.currPeState.isa)
			d.outputElem.LastInstrCond = d.instrInfo.IsConditional != 0
			respErr = d.OutputTraceElementIdx(d.IndexCurrPkt, d.csID, &d.outputElem)
		}
	}
	return respErr
}

func (d *PktDecode) traceInstrToWP(traceWPOp waypointTraceOp, nextAddrMatch ocsd.VAddr) (wpFound bool, err error) {
	err = nil
	var bytesReq uint32
	var currOpAddress ocsd.VAddr

	memSpace := ocsd.MemSpaceEL1N
	if d.peContext.SecurityLevel == ocsd.SecSecure {
		memSpace = ocsd.MemSpaceEL1S
	}

	d.outputElem.StartAddr = d.instrInfo.InstrAddr
	d.outputElem.EndAddr = d.instrInfo.InstrAddr
	d.outputElem.Payload.NumInstrRange = 0

	wpFound = false

	for !wpFound && !d.memNaccPending {
		bytesReq = 4
		currOpAddress = d.instrInfo.InstrAddr
		bytesRead, memData, errMem := d.AccessMemory(d.instrInfo.InstrAddr, d.csID, memSpace, bytesReq)
		if errMem != nil {
			if errors.Is(errMem, memacc.ErrNoAccessor) {
				d.memNaccPending = true
				d.naccAddr = d.instrInfo.InstrAddr
				break
			}
			err = errMem
			break
		}

		canDecode := bytesRead == 4
		if !canDecode && d.instrInfo.ISA == ocsd.ISAThumb2 && bytesRead >= 2 {
			instHW := uint16(memData[0]) | uint16(memData[1])<<8
			if !idec.IsWideThumb(instHW) {
				canDecode = true
			}
		}

		if canDecode {
			opcode := uint32(0)
			if bytesRead >= 1 {
				opcode |= uint32(memData[0])
			}
			if bytesRead >= 2 {
				opcode |= uint32(memData[1]) << 8
			}
			if bytesRead >= 3 {
				opcode |= uint32(memData[2]) << 16
			}
			if bytesRead >= 4 {
				opcode |= uint32(memData[3]) << 24
			}
			d.instrInfo.Opcode = opcode
			err = d.InstrDecodeCall(&d.instrInfo)
			if err != nil {
				break
			}

			d.instrInfo.InstrAddr += ocsd.VAddr(d.instrInfo.InstrSize)
			d.outputElem.EndAddr = d.instrInfo.InstrAddr
			d.outputElem.Payload.NumInstrRange++
			d.outputElem.LastInstrType = d.instrInfo.Type

			if traceWPOp != traceWaypoint {
				if traceWPOp == traceToAddrExcl {
					wpFound = d.outputElem.EndAddr == nextAddrMatch
				} else {
					wpFound = currOpAddress == nextAddrMatch
				}
			} else {
				wpFound = d.instrInfo.Type != ocsd.InstrOther
			}
		} else {
			d.memNaccPending = true
			d.naccAddr = d.instrInfo.InstrAddr
		}
	}
	return wpFound, err
}
