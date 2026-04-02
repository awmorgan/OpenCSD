package stm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"

	"opencsd/internal/common"
	"opencsd/internal/ocsd"
)

type processState int

const (
	procWaitSync processState = iota
	procHdrState
	procDataState
	procSendPkt
)

var stmPacketDataPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 64)
		return &b
	},
}

type decodeAction int

const (
	decodeNone decodeAction = iota
	decodePktReserved
	decodePktNull
	decodePktNullTS
	decodePktM8
	decodePktMERR
	decodePktC8
	decodePktD4
	decodePktD8
	decodePktD16
	decodePktD32
	decodePktD64
	decodePktD4MTS
	decodePktD8MTS
	decodePktD16MTS
	decodePktD32MTS
	decodePktD64MTS
	decodePktFlagTS
	decodePktFExt
	decodePktReservedFn
	decodePktF0Ext
	decodePktGERR
	decodePktC16
	decodePktD4TS
	decodePktD8TS
	decodePktD16TS
	decodePktD32TS
	decodePktD64TS
	decodePktD4M
	decodePktD8M
	decodePktD16M
	decodePktD32M
	decodePktD64M
	decodePktFlag
	decodePktReservedF0n
	decodePktVersion
	decodePktTrigger
	decodePktTriggerTS
	decodePktFreq
	decodePktASync
	decodeExtractTS
)

type procStateFn func(ocsd.TrcIndex) (ocsd.DatapathResp, error, bool)

// PktProc converts the byte stream into basic STM trace packets.
type PktProc struct {
	Name       string
	opMode     common.OpMode
	Stats      ocsd.DecodeStats
	statsInit  bool
	Config     *Config
	pktOut     ocsd.PacketProcessorExplicit[Packet]
	PktRawMonI ocsd.PacketMonitor

	procState processState

	op1N [0x10]decodeAction
	op2N [0x10]decodeAction
	op3N [0x10]decodeAction

	currDecode decodeAction

	currPacket Packet
	bNeedsTS   bool
	bIsMarker  bool
	streamSync bool

	numNibbles     uint8
	nibble         uint8
	nibble2nd      uint8
	nibble2ndValid bool
	numDataNibbles uint8

	dataIn      []byte
	dataInSize  uint32
	dataInUsed  uint32
	blockReader *bytes.Reader
	dataReader  *bufio.Reader
	packetIndex ocsd.TrcIndex

	packetData              []byte
	packetDataRef           *[]byte
	bWaitSyncSaveSuppressed bool

	val8  uint8
	val16 uint16
	val32 uint32
	val64 uint64

	reqTSNibbles  uint8
	currTSNibbles uint8
	tsUpdateValue uint64
	tsReqSet      bool

	numFNibbles uint8
	syncStart   bool
	isSync      bool
	syncIndex   ocsd.TrcIndex
}

func (p *PktProc) ComponentOpMode() uint32  { return p.opMode.ComponentOpMode() }
func (p *PktProc) SupportedOpModes() uint32 { return p.opMode.SupportedOpModes() }
func (p *PktProc) SetComponentOpMode(opFlags uint32) error {
	return p.opMode.SetComponentOpMode(opFlags)
}
func (p *PktProc) ConfigureSupportedOpModes(flags uint32) { p.opMode.ConfigureSupportedOpModes(flags) }

func NewPktProc(cfg *Config) *PktProc {
	instIDNum := 0
	if cfg != nil {
		instIDNum = int(cfg.TraceID())
	}
	p := &PktProc{
		Name: fmt.Sprintf("PKTP_STM_%d", instIDNum),
	}
	p.packetDataRef = stmGetPacketBufRef()
	p.packetData = (*p.packetDataRef)[:0]
	p.ResetStats()
	p.ConfigureSupportedOpModes(ocsd.OpflgPktprocCommon)
	p.resetProcessorState()
	p.buildOpTables()
	if cfg != nil {
		_ = p.SetProtocolConfig(cfg)
	}
	return p
}

// SetPktOut attaches the downstream packet decoder.
func (p *PktProc) SetPktOut(out ocsd.PacketProcessorExplicit[Packet]) { p.pktOut = out }

// SetPktRawMonitor attaches a raw packet monitor.
func (p *PktProc) SetPktRawMonitor(mon ocsd.PacketMonitor) { p.PktRawMonI = mon }

// HasRawMon reports whether a raw packet monitor is attached.
func (p *PktProc) HasRawMon() bool { return p.PktRawMonI != nil }

// StatsBlock returns the decode statistics, or ErrNotInit if not yet initialized.
func (p *PktProc) StatsBlock() (*ocsd.DecodeStats, error) {
	if !p.statsInit {
		return &p.Stats, ocsd.ErrNotInit
	}
	return &p.Stats, nil
}

// StatsInit marks the statistics block as initialized.
func (p *PktProc) StatsInit() { p.statsInit = true }

// ResetStats zeroes all decode statistics fields.
func (p *PktProc) ResetStats() {
	p.Stats.Version = ocsd.VerNum
	p.Stats.Revision = ocsd.StatsRevision
	p.Stats.ChannelTotal = 0
	p.Stats.ChannelUnsynced = 0
	p.Stats.BadHeaderErrs = 0
	p.Stats.BadSequenceErrs = 0
	p.Stats.Demux.FrameBytes = 0
	p.Stats.Demux.NoIDBytes = 0
	p.Stats.Demux.ValidIDBytes = 0
}

// StatsAddTotalCount adds to the total channel bytes counter.
func (p *PktProc) StatsAddTotalCount(count uint64) { p.Stats.ChannelTotal += count }

// StatsAddUnsyncCount adds to the unsynced channel bytes counter.
func (p *PktProc) StatsAddUnsyncCount(count uint64) { p.Stats.ChannelUnsynced += count }

// StatsAddBadSeqCount adds to the bad-sequence-error counter.
func (p *PktProc) StatsAddBadSeqCount(count uint32) { p.Stats.BadSequenceErrs += count }

// StatsAddBadHdrCount adds to the bad-header-error counter.
func (p *PktProc) StatsAddBadHdrCount(count uint32) { p.Stats.BadHeaderErrs += count }

func (p *PktProc) outputDecodedPacket(indexSOP ocsd.TrcIndex, pkt *Packet) ocsd.DatapathResp {
	if p.pktOut != nil {
		return ocsd.DataRespFromErr(p.callPktOut(ocsd.OpData, indexSOP, pkt))
	}
	return ocsd.RespCont
}

func (p *PktProc) callPktOut(op ocsd.DatapathOp, indexSOP ocsd.TrcIndex, pkt *Packet) error {
	if p.pktOut == nil {
		return nil
	}
	switch op {
	case ocsd.OpData:
		return p.pktOut.TracePacketData(indexSOP, pkt)
	case ocsd.OpEOT:
		return p.pktOut.TracePacketEOT()
	case ocsd.OpFlush:
		return p.pktOut.TracePacketFlush()
	case ocsd.OpReset:
		return p.pktOut.TracePacketReset(indexSOP)
	default:
		return ocsd.ErrInvalidParamVal
	}
}

func (p *PktProc) outputRawPacketToMonitor(indexSOP ocsd.TrcIndex, pkt *Packet, pData []byte) {
	if p.PktRawMonI != nil && len(pData) > 0 {
		p.PktRawMonI.RawPacketDataMon(ocsd.OpData, indexSOP, pkt, pData)
	}
}

func (p *PktProc) outputOnAllInterfaces(indexSOP ocsd.TrcIndex, pkt *Packet, pktData []byte) ocsd.DatapathResp {
	if len(pktData) > 0 {
		p.outputRawPacketToMonitor(indexSOP, pkt, pktData)
	}
	return p.outputDecodedPacket(indexSOP, pkt)
}

func (p *PktProc) TraceDataIn(op ocsd.DatapathOp, index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	resp := ocsd.RespCont
	var processed uint32 = 0
	var err error

	switch op {
	case ocsd.OpData:
		if len(dataBlock) == 0 {
			err = fmt.Errorf("%w: packet processor: zero length data block", ocsd.ErrInvalidParamVal)
			resp = ocsd.RespFatalInvalidParam
		} else {
			processed, err = p.ProcessData(index, dataBlock)
			resp = ocsd.DataRespFromErr(err)
		}
	case ocsd.OpEOT:
		resp = p.OnEOT()
		if p.pktOut != nil && !ocsd.DataRespIsFatal(resp) {
			err = p.callPktOut(ocsd.OpEOT, 0, nil)
			resp = ocsd.DataRespFromErr(err)
			if ocsd.IsDataWaitErr(err) {
				err = nil
			}
		}
		if rawMon := p.PktRawMonI; rawMon != nil {
			rawMon.RawPacketDataMon(ocsd.OpEOT, 0, nil, nil)
		}
	case ocsd.OpFlush:
		resp = p.OnFlush()
		if ocsd.DataRespIsCont(resp) && p.pktOut != nil {
			err = p.callPktOut(ocsd.OpFlush, 0, nil)
			resp = ocsd.DataRespFromErr(err)
			if ocsd.IsDataWaitErr(err) {
				err = nil
			}
		}
	case ocsd.OpReset:
		if p.pktOut != nil {
			err = p.callPktOut(ocsd.OpReset, index, nil)
			resp = ocsd.DataRespFromErr(err)
			if ocsd.IsDataWaitErr(err) {
				err = nil
			}
		}
		if !ocsd.DataRespIsFatal(resp) {
			resp = p.OnReset()
		}
		if rawMon := p.PktRawMonI; rawMon != nil {
			rawMon.RawPacketDataMon(ocsd.OpReset, index, nil, nil)
		}
	default:
		err = fmt.Errorf("%w: packet processor: unknown datapath operation", ocsd.ErrInvalidParamVal)
		resp = ocsd.RespFatalInvalidOp
	}
	if ocsd.DataRespIsCont(resp) {
		return processed, nil
	}
	if ocsd.DataRespIsWait(resp) {
		return processed, ocsd.ErrWait
	}
	if err != nil {
		return processed, err
	}
	switch resp {
	case ocsd.RespFatalNotInit:
		return processed, ocsd.ErrNotInit
	case ocsd.RespFatalInvalidParam, ocsd.RespFatalInvalidOp:
		return processed, ocsd.ErrInvalidParamVal
	case ocsd.RespFatalSysErr:
		return processed, ocsd.ErrFail
	default:
		return processed, ocsd.ErrDataDecodeFatal
	}
}

// TraceData is the explicit data-path entrypoint used by split interfaces.
func (p *PktProc) TraceData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	return p.TraceDataIn(ocsd.OpData, index, dataBlock)
}

// TraceDataEOT forwards an EOT control operation through the legacy multiplexer.
func (p *PktProc) TraceDataEOT() error {
	_, err := p.TraceDataIn(ocsd.OpEOT, 0, nil)
	return err
}

// TraceDataFlush forwards a flush control operation through the legacy multiplexer.
func (p *PktProc) TraceDataFlush() error {
	_, err := p.TraceDataIn(ocsd.OpFlush, 0, nil)
	return err
}

// TraceDataReset forwards a reset control operation through the legacy multiplexer.
func (p *PktProc) TraceDataReset(index ocsd.TrcIndex) error {
	_, err := p.TraceDataIn(ocsd.OpReset, index, nil)
	return err
}

func (p *PktProc) ProcessData(index ocsd.TrcIndex, dataBlock []byte) (uint32, error) {
	resp := ocsd.RespCont
	var err error
	p.dataIn = dataBlock
	p.dataInSize = uint32(len(dataBlock))
	p.dataInUsed = 0
	p.blockReader = bytes.NewReader(dataBlock)
	p.dataReader = bufio.NewReaderSize(p.blockReader, 4096)

	for p.dataToProcess() && ocsd.DataRespIsCont(resp) {
		errResp, loopErr, handled := p.processStateLoop(index)
		if handled {
			resp = errResp
			err = loopErr
			if ocsd.DataRespIsFatal(resp) {
				break
			}
			if err != nil {
				break
			}
		}
	}

	if ocsd.DataRespIsCont(resp) {
		return p.dataInUsed, nil
	}
	if ocsd.DataRespIsWait(resp) {
		return p.dataInUsed, ocsd.ErrWait
	}
	if err != nil {
		return p.dataInUsed, err
	}
	return p.dataInUsed, ocsd.DataErrFromResp(resp, nil)
}

func (p *PktProc) processStateLoop(index ocsd.TrcIndex) (resp ocsd.DatapathResp, err error, handled bool) {
	fn := p.currentProcStateFn()
	if fn == nil {
		return ocsd.RespCont, nil, false
	}
	return fn(index)
}

func (p *PktProc) currentProcStateFn() procStateFn {
	switch p.procState {
	case procWaitSync:
		return p.stateWaitSync
	case procHdrState:
		return p.stateHdr
	case procDataState:
		return p.stateData
	case procSendPkt:
		return p.stateSendPkt
	default:
		return nil
	}
}

func (p *PktProc) stateWaitSync(index ocsd.TrcIndex) (ocsd.DatapathResp, error, bool) {
	p.waitForSync(index)
	if p.procState == procSendPkt {
		return p.stateSendPkt(index)
	}
	return ocsd.RespCont, nil, false
}

func (p *PktProc) stateHdr(index ocsd.TrcIndex) (ocsd.DatapathResp, error, bool) {
	p.packetIndex = index + ocsd.TrcIndex(p.dataInUsed)
	if p.readNibble() {
		p.procState = procDataState
		p.currDecode = p.op1N[p.nibble]
		return p.stateData(index)
	}
	return ocsd.RespCont, nil, false
}

func (p *PktProc) stateData(index ocsd.TrcIndex) (ocsd.DatapathResp, error, bool) {
	err := p.runDecodeAction()
	if errResp, loopErr, errHandled := p.handleProcError(err); errHandled {
		return errResp, loopErr, true
	}
	if p.procState == procSendPkt {
		return p.stateSendPkt(index)
	}
	return ocsd.RespCont, nil, false
}

func (p *PktProc) stateSendPkt(_ ocsd.TrcIndex) (ocsd.DatapathResp, error, bool) {
	resp := p.outputPacket()
	return resp, nil, true
}

func (p *PktProc) handleProcError(err error) (resp ocsd.DatapathResp, outErr error, handled bool) {
	if err == nil {
		return ocsd.RespCont, nil, false
	}

	if (errors.Is(err, ocsd.ErrBadPacketSeq) || errors.Is(err, ocsd.ErrInvalidPcktHdr)) &&
		(p.ComponentOpMode()&ocsd.OpflgPktprocErrBadPkts) == 0 {
		resp = p.outputPacket()
		if (p.ComponentOpMode() & ocsd.OpflgPktprocUnsyncOnBadPkts) != 0 {
			p.procState = procWaitSync
		}
		return resp, err, true
	}
	return ocsd.RespFatalInvalidData, err, true
}

func (p *PktProc) OnEOT() ocsd.DatapathResp {
	resp := ocsd.RespCont
	if p.numNibbles > 0 {
		p.currPacket.OrigType = p.currPacket.Type
		p.currPacket.SetPacketType(PktIncompleteEOT, false)
		resp = p.outputPacket()
	}
	return resp
}

func (p *PktProc) OnReset() ocsd.DatapathResp {
	p.resetProcessorState()
	return ocsd.RespCont
}

func (p *PktProc) OnFlush() ocsd.DatapathResp {
	return ocsd.RespCont
}

func (p *PktProc) SetProtocolConfig(config *Config) error {
	p.Config = config
	return nil
}

func (p *PktProc) IsBadPacket() bool {
	return p.currPacket.IsBadPacket()
}

func (p *PktProc) outputPacket() ocsd.DatapathResp {
	pktData := p.packetData
	resp := p.outputOnAllInterfaces(p.packetIndex, &p.currPacket, pktData)
	stmPutPacketBufRef(p.packetDataRef, pktData)
	p.packetDataRef = stmGetPacketBufRef()
	p.packetData = (*p.packetDataRef)[:0]
	p.resetNextPacket()
	if p.nibble2ndValid {
		p.savePacketByte(p.nibble2nd << 4)
	}
	if p.streamSync {
		p.procState = procHdrState
	} else {
		p.procState = procWaitSync
	}
	return resp
}

// setBadSequenceError records a bad-sequence error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setBadSequenceError(msg string) error {
	p.currPacket.OrigType = p.currPacket.Type
	p.currPacket.SetPacketType(PktBadSequence, false)
	return fmt.Errorf("%w: %s", ocsd.ErrBadPacketSeq, msg)
}

// setReservedHdrError records a reserved-header error on the processor.
// Callers must return immediately after calling this.
func (p *PktProc) setReservedHdrError(msg string) error {
	p.currPacket.OrigType = p.currPacket.Type
	p.currPacket.SetPacketType(PktReserved, false)
	return fmt.Errorf("%w: %s", ocsd.ErrInvalidPcktHdr, msg)
}

func (p *PktProc) resetProcessorState() {
	p.setProcUnsynced()
	p.clearSyncCount()
	p.currPacket.ResetStartState()
	p.nibble2ndValid = false
	p.resetNextPacket()
	p.bWaitSyncSaveSuppressed = false
	if p.packetData == nil {
		p.packetDataRef = stmGetPacketBufRef()
		p.packetData = (*p.packetDataRef)[:0]
	}
}

func (p *PktProc) resetNextPacket() {
	p.bNeedsTS = false
	p.bIsMarker = false
	p.numNibbles = 0
	p.numDataNibbles = 0
	p.currDecode = decodeNone
	p.currPacket.ResetNextPacket()
}

func (p *PktProc) runDecodeAction() error {
	switch p.currDecode {
	case decodePktReserved:
		return p.PktReserved()
	case decodePktNull:
		return p.PktNull()
	case decodePktNullTS:
		return p.PktNullTS()
	case decodePktM8:
		return p.PktM8()
	case decodePktMERR:
		return p.PktMERR()
	case decodePktC8:
		return p.PktC8()
	case decodePktD4:
		return p.PktD4()
	case decodePktD8:
		return p.PktD8()
	case decodePktD16:
		return p.PktD16()
	case decodePktD32:
		return p.PktD32()
	case decodePktD64:
		return p.PktD64()
	case decodePktD4MTS:
		return p.PktD4MTS()
	case decodePktD8MTS:
		return p.PktD8MTS()
	case decodePktD16MTS:
		return p.PktD16MTS()
	case decodePktD32MTS:
		return p.PktD32MTS()
	case decodePktD64MTS:
		return p.PktD64MTS()
	case decodePktFlagTS:
		return p.PktFlagTS()
	case decodePktFExt:
		return p.PktFExt()
	case decodePktReservedFn:
		return p.PktReservedFn()
	case decodePktF0Ext:
		return p.PktF0Ext()
	case decodePktGERR:
		return p.PktGERR()
	case decodePktC16:
		return p.PktC16()
	case decodePktD4TS:
		return p.PktD4TS()
	case decodePktD8TS:
		return p.PktD8TS()
	case decodePktD16TS:
		return p.PktD16TS()
	case decodePktD32TS:
		return p.PktD32TS()
	case decodePktD64TS:
		return p.PktD64TS()
	case decodePktD4M:
		return p.PktD4M()
	case decodePktD8M:
		return p.PktD8M()
	case decodePktD16M:
		return p.PktD16M()
	case decodePktD32M:
		return p.PktD32M()
	case decodePktD64M:
		return p.PktD64M()
	case decodePktFlag:
		return p.PktFlag()
	case decodePktReservedF0n:
		return p.PktReservedF0n()
	case decodePktVersion:
		return p.PktVersion()
	case decodePktTrigger:
		return p.PktTrigger()
	case decodePktTriggerTS:
		return p.PktTriggerTS()
	case decodePktFreq:
		return p.PktFreq()
	case decodePktASync:
		return p.PktASync()
	case decodeExtractTS:
		return p.ExtractTS()
	default:
		return p.setBadSequenceError("STM decode action not set")
	}
}

func (p *PktProc) waitForSync(blkStIndex ocsd.TrcIndex) {
	bGotData := true
	startOffset := p.dataInUsed

	p.packetIndex = blkStIndex + ocsd.TrcIndex(p.dataInUsed)
	p.numNibbles = p.numFNibbles
	if p.isSync {
		p.numNibbles++
	}

	p.bWaitSyncSaveSuppressed = true
	for bGotData && !p.isSync {
		bGotData = p.readNibble()
	}
	p.bWaitSyncSaveSuppressed = false

	if p.numNibbles == 0 {
		return
	}

	if !bGotData || p.numNibbles > 22 {
		p.currPacket.SetPacketType(PktNotSync, false)
		if p.PktRawMonI != nil {
			nibblesToSend := max(int(p.numNibbles)-int(p.numFNibbles), 0)
			if p.isSync {
				nibblesToSend = max(int(p.numNibbles)-22, 0)
			}
			bytesToSend := uint32((nibblesToSend / 2) + (nibblesToSend % 2))
			// Clamp output to the bytes actually consumed in this cycle
			// to prevent reading unparsed future bytes or out-of-bounds memory.
			consumedBytes := p.dataInUsed - startOffset
			if bytesToSend > consumedBytes {
				bytesToSend = consumedBytes
			}
			for i := range bytesToSend {
				p.savePacketByte(p.dataIn[startOffset+i])
			}
		}
	} else {
		p.currPacket.SetPacketType(PktAsync, false)
		p.streamSync = true
		p.clearSyncCount()
		p.packetIndex = p.syncIndex
		if p.PktRawMonI != nil {
			for range 10 {
				p.savePacketByte(0xFF)
			}
			p.savePacketByte(0x0F)
		}
	}
	p.sendPacket()
}

func (p *PktProc) PktReserved() error {
	badOpcode := uint16(p.nibble)
	p.currPacket.Payload.D16 = badOpcode
	return p.setReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) PktNull() error {
	p.currPacket.SetPacketType(PktNull, false)
	if p.bNeedsTS {
		p.currDecode = decodeExtractTS
		return p.runDecodeAction()
	} else {
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktNullTS() error {
	p.pktNeedsTS()
	p.currDecode = decodePktNull
	return p.runDecodeAction()
}

func (p *PktProc) PktM8() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktM8, false)
	}
	p.ExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetMaster(p.val8)
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktMERR() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktMErr, false)
	}
	p.ExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetChannel(0, false)
		p.currPacket.Payload.D8 = p.val8
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktC8() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktC8, false)
	}
	p.ExtractVal8(3)
	if p.numNibbles == 3 {
		p.currPacket.SetChannel(uint16(p.val8), true)
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktD4() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD4, p.bIsMarker)
		p.numDataNibbles = 2
	}
	if p.numNibbles != p.numDataNibbles {
		if p.readNibble() {
			p.currPacket.SetD4Payload(p.nibble)
			if p.bNeedsTS {
				p.currDecode = decodeExtractTS
				return p.runDecodeAction()
			} else {
				p.sendPacket()
			}
		}
	}
	return nil
}

func (p *PktProc) PktD8() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD8, p.bIsMarker)
		p.numDataNibbles = 3
	}
	p.ExtractVal8(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.Payload.D8 = p.val8
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			return p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
	return nil
}

func (p *PktProc) PktD16() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD16, p.bIsMarker)
		p.numDataNibbles = 5
	}
	p.ExtractVal16(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.Payload.D16 = p.val16
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			return p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
	return nil
}

func (p *PktProc) PktD32() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD32, p.bIsMarker)
		p.numDataNibbles = 9
	}
	p.ExtractVal32(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.Payload.D32 = p.val32
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			return p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
	return nil
}

func (p *PktProc) PktD64() error {
	if p.numNibbles == 1 {
		p.currPacket.SetPacketType(PktD64, p.bIsMarker)
		p.numDataNibbles = 17
	}
	p.ExtractVal64(p.numDataNibbles)
	if p.numNibbles == p.numDataNibbles {
		p.currPacket.Payload.D64 = p.val64
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			return p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
	return nil
}

func (p *PktProc) PktD4MTS() error {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD4
	return p.runDecodeAction()
}

func (p *PktProc) PktD8MTS() error {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD8
	return p.runDecodeAction()
}

func (p *PktProc) PktD16MTS() error {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD16
	return p.runDecodeAction()
}

func (p *PktProc) PktD32MTS() error {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD32
	return p.runDecodeAction()
}

func (p *PktProc) PktD64MTS() error {
	p.pktNeedsTS()
	p.bIsMarker = true
	p.currDecode = decodePktD64
	return p.runDecodeAction()
}

func (p *PktProc) PktFlagTS() error {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktFlag, false)
	p.currDecode = decodeExtractTS
	return p.runDecodeAction()
}

func (p *PktProc) PktFExt() error {
	if p.readNibble() {
		p.currDecode = p.op2N[p.nibble]
		return p.runDecodeAction()
	}
	return nil
}

func (p *PktProc) PktReservedFn() error {
	badOpcode := uint16(0x00F) | (uint16(p.nibble) << 4)
	p.currPacket.Payload.D16 = badOpcode
	return p.setReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) PktF0Ext() error {
	if p.readNibble() {
		p.currDecode = p.op3N[p.nibble]
		return p.runDecodeAction()
	}
	return nil
}

func (p *PktProc) PktGERR() error {
	if p.numNibbles == 2 {
		p.currPacket.SetPacketType(PktGErr, false)
	}
	p.ExtractVal8(4)
	if p.numNibbles == 4 {
		p.currPacket.Payload.D8 = p.val8
		p.currPacket.SetMaster(0)
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktC16() error {
	if p.numNibbles == 2 {
		p.currPacket.SetPacketType(PktC16, false)
	}
	p.ExtractVal16(6)
	if p.numNibbles == 6 {
		p.currPacket.SetChannel(p.val16, false)
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktD4TS() error {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD4, false)
	p.numDataNibbles = 3
	p.currDecode = decodePktD4
	return p.runDecodeAction()
}

func (p *PktProc) PktD8TS() error {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD8, false)
	p.numDataNibbles = 4
	p.currDecode = decodePktD8
	return p.runDecodeAction()
}

func (p *PktProc) PktD16TS() error {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD16, false)
	p.numDataNibbles = 6
	p.currDecode = decodePktD16
	return p.runDecodeAction()
}

func (p *PktProc) PktD32TS() error {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD32, false)
	p.numDataNibbles = 10
	p.currDecode = decodePktD32
	return p.runDecodeAction()
}

func (p *PktProc) PktD64TS() error {
	p.pktNeedsTS()
	p.currPacket.SetPacketType(PktD64, false)
	p.numDataNibbles = 18
	p.currDecode = decodePktD64
	return p.runDecodeAction()
}

func (p *PktProc) PktD4M() error {
	p.currPacket.SetPacketType(PktD4, true)
	p.numDataNibbles = 3
	p.currDecode = decodePktD4
	return p.runDecodeAction()
}

func (p *PktProc) PktD8M() error {
	p.currPacket.SetPacketType(PktD8, true)
	p.numDataNibbles = 4
	p.currDecode = decodePktD8
	return p.runDecodeAction()
}

func (p *PktProc) PktD16M() error {
	p.currPacket.SetPacketType(PktD16, true)
	p.numDataNibbles = 6
	p.currDecode = decodePktD16
	return p.runDecodeAction()
}

func (p *PktProc) PktD32M() error {
	p.currPacket.SetPacketType(PktD32, true)
	p.numDataNibbles = 10
	p.currDecode = decodePktD32
	return p.runDecodeAction()
}

func (p *PktProc) PktD64M() error {
	p.currPacket.SetPacketType(PktD64, true)
	p.numDataNibbles = 18
	p.currDecode = decodePktD64
	return p.runDecodeAction()
}

func (p *PktProc) PktFlag() error {
	p.currPacket.SetPacketType(PktFlag, false)
	p.sendPacket()
	return nil
}

func (p *PktProc) PktReservedF0n() error {
	badOpcode := uint16(0x00F) | (uint16(p.nibble) << 8)
	p.currPacket.Payload.D16 = badOpcode
	return p.setReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (p *PktProc) PktVersion() error {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktVersion, false)
	}
	if p.readNibble() {
		p.currPacket.Payload.D8 = p.nibble
		switch p.nibble {
		case 3:
			p.currPacket.OnVersionPkt(TSNatBinary)
		case 4:
			p.currPacket.OnVersionPkt(TSGrey)
		default:
			return p.setBadSequenceError("STM VERSION packet : unrecognised version number.")
		}
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktTrigger() error {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktTrig, false)
	}
	p.ExtractVal8(5)
	if p.numNibbles == 5 {
		p.currPacket.Payload.D8 = p.val8
		if p.bNeedsTS {
			p.currDecode = decodeExtractTS
			return p.runDecodeAction()
		} else {
			p.sendPacket()
		}
	}
	return nil
}

func (p *PktProc) PktTriggerTS() error {
	p.pktNeedsTS()
	p.currDecode = decodePktTrigger
	return p.runDecodeAction()
}

func (p *PktProc) PktFreq() error {
	if p.numNibbles == 3 {
		p.currPacket.SetPacketType(PktFreq, false)
		p.val32 = 0
	}
	p.ExtractVal32(11)
	if p.numNibbles == 11 {
		p.currPacket.Payload.D32 = p.val32
		p.sendPacket()
	}
	return nil
}

func (p *PktProc) PktASync() error {
	bCont := true
	for bCont {
		bCont = p.readNibble()
		if bCont {
			if p.isSync {
				bCont = false
				p.streamSync = true
				p.currPacket.SetPacketType(PktAsync, false)
				p.clearSyncCount()
				p.sendPacket()
			} else if !p.syncStart {
				return p.setBadSequenceError("STM: Invalid ASYNC sequence")
			}
		}
	}
	return nil
}

func (p *PktProc) readNibble() bool {
	dataFound := true
	if p.nibble2ndValid {
		p.nibble = p.nibble2nd
		p.nibble2ndValid = false
		p.numNibbles++
		p.checkSyncNibble()
	} else {
		streamByte, ok := p.readStreamByte()
		if !ok {
			return false
		}
		p.nibble = streamByte
		p.savePacketByte(p.nibble)
		p.nibble2nd = (p.nibble >> 4) & 0xF
		p.nibble2ndValid = true
		p.nibble &= 0xF
		p.numNibbles++
		p.checkSyncNibble()
	}
	return dataFound
}

func (p *PktProc) readStreamByte() (byte, bool) {
	if p.dataReader == nil {
		return 0, false
	}
	var single [1]byte
	_, err := io.ReadFull(p.dataReader, single[:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, false
		}
		return 0, false
	}
	p.refreshDataUsed()
	return single[0], true
}

func (p *PktProc) refreshDataUsed() {
	if p.blockReader == nil || p.dataReader == nil {
		return
	}
	remaining := p.blockReader.Len() + p.dataReader.Buffered()
	p.dataInUsed = p.dataInSize - uint32(remaining)
}

func (p *PktProc) pktNeedsTS() {
	p.bNeedsTS = true
	p.reqTSNibbles = 0
	p.currTSNibbles = 0
	p.tsUpdateValue = 0
	p.tsReqSet = false
}

func (p *PktProc) ExtractTS() error {
	if !p.tsReqSet {
		if p.readNibble() {
			p.reqTSNibbles = p.nibble
			switch p.nibble {
			case 0xD:
				p.reqTSNibbles = 14
			case 0xE:
				p.reqTSNibbles = 16
			}
			if p.nibble == 0xF {
				return p.setBadSequenceError("STM: Invalid timestamp size 0xF")
			}
			p.tsReqSet = true
		}
	}

	if p.tsReqSet {
		if p.reqTSNibbles != p.currTSNibbles {
			bCont := true
			for bCont && (p.currTSNibbles < p.reqTSNibbles) {
				bCont = p.readNibble()
				if bCont {
					if p.tsUpdateValue > 0x0FFFFFFFFFFFFFFF {
						return p.setBadSequenceError("STM: malformed timestamp overflow")
					}
					p.tsUpdateValue <<= 4
					p.tsUpdateValue |= uint64(p.nibble)
					p.currTSNibbles++
				}
			}
		}

		if p.reqTSNibbles == p.currTSNibbles {
			newBits := p.reqTSNibbles * 4
			switch p.currPacket.TSType {
			case TSGrey:
				grayVal := p.binToGray(p.currPacket.Timestamp)
				if newBits == 64 {
					grayVal = p.tsUpdateValue
				} else {
					mask := (uint64(1) << newBits) - 1
					grayVal &^= mask
					grayVal |= p.tsUpdateValue & mask
				}
				p.currPacket.SetTS(p.grayToBin(grayVal), newBits)
			case TSNatBinary:
				p.currPacket.SetTS(p.tsUpdateValue, newBits)
			default:
				return p.setBadSequenceError("STM: unknown timestamp encoding")
			}
			p.sendPacket()
		}
	}
	return nil
}

func (p *PktProc) ExtractVal8(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val8 <<= 4
			p.val8 |= p.nibble
		}
	}
}

func (p *PktProc) ExtractVal16(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val16 <<= 4
			p.val16 |= uint16(p.nibble)
		}
	}
}

func (p *PktProc) ExtractVal32(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val32 <<= 4
			p.val32 |= uint32(p.nibble)
		}
	}
}

func (p *PktProc) ExtractVal64(nibblesToVal uint8) {
	bCont := true
	for bCont && (p.numNibbles < nibblesToVal) {
		bCont = p.readNibble()
		if bCont {
			p.val64 <<= 4
			p.val64 |= uint64(p.nibble)
		}
	}
}

func (p *PktProc) binToGray(binValue uint64) uint64 {
	return binValue ^ (binValue >> 1)
}

func (p *PktProc) grayToBin(grayValue uint64) uint64 {
	binValue := grayValue
	for shift := uint(1); shift < 64; shift <<= 1 {
		binValue ^= binValue >> shift
	}
	return binValue
}

func (p *PktProc) buildOpTables() {
	for i := range 0x10 {
		p.op1N[i] = decodePktReserved
		p.op2N[i] = decodePktReservedFn
		p.op3N[i] = decodePktReservedF0n
	}

	p.op1N[0x0] = decodePktNull
	p.op1N[0x1] = decodePktM8
	p.op1N[0x2] = decodePktMERR
	p.op1N[0x3] = decodePktC8
	p.op1N[0x4] = decodePktD8
	p.op1N[0x5] = decodePktD16
	p.op1N[0x6] = decodePktD32
	p.op1N[0x7] = decodePktD64
	p.op1N[0x8] = decodePktD8MTS
	p.op1N[0x9] = decodePktD16MTS
	p.op1N[0xA] = decodePktD32MTS
	p.op1N[0xB] = decodePktD64MTS
	p.op1N[0xC] = decodePktD4
	p.op1N[0xD] = decodePktD4MTS
	p.op1N[0xE] = decodePktFlagTS
	p.op1N[0xF] = decodePktFExt

	p.op2N[0x0] = decodePktF0Ext
	p.op2N[0x2] = decodePktGERR
	p.op2N[0x3] = decodePktC16
	p.op2N[0x4] = decodePktD8TS
	p.op2N[0x5] = decodePktD16TS
	p.op2N[0x6] = decodePktD32TS
	p.op2N[0x7] = decodePktD64TS
	p.op2N[0x8] = decodePktD8M
	p.op2N[0x9] = decodePktD16M
	p.op2N[0xA] = decodePktD32M
	p.op2N[0xB] = decodePktD64M
	p.op2N[0xC] = decodePktD4TS
	p.op2N[0xD] = decodePktD4M
	p.op2N[0xE] = decodePktFlag
	p.op2N[0xF] = decodePktASync

	p.op3N[0x0] = decodePktVersion
	p.op3N[0x1] = decodePktNullTS
	p.op3N[0x6] = decodePktTrigger
	p.op3N[0x7] = decodePktTriggerTS
	p.op3N[0x8] = decodePktFreq
}

func (p *PktProc) checkSyncNibble() {
	if p.nibble != 0xF {
		if !p.syncStart {
			return
		}
		if p.nibble == 0 && p.numFNibbles >= 21 {
			p.isSync = true
			p.numFNibbles = 21
		} else {
			p.clearSyncCount()
		}
		return
	}

	p.numFNibbles++
	if !p.syncStart {
		p.syncStart = true
		p.syncIndex = p.packetIndex + ocsd.TrcIndex((p.numNibbles-1)/2)
	}
}

func (p *PktProc) clearSyncCount() {
	p.numFNibbles = 0
	p.syncStart = false
	p.isSync = false
}

func (p *PktProc) sendPacket() {
	p.procState = procSendPkt
}

func (p *PktProc) setProcUnsynced() {
	p.procState = procWaitSync
	p.streamSync = false
}

func (p *PktProc) savePacketByte(val uint8) {
	if p.PktRawMonI != nil && !p.bWaitSyncSaveSuppressed {
		p.packetData = append(p.packetData, val)
	}
}

func (p *PktProc) dataToProcess() bool {
	hasStream := p.dataReader != nil && (p.dataReader.Buffered() > 0 || (p.blockReader != nil && p.blockReader.Len() > 0))
	return hasStream || p.nibble2ndValid || (p.procState == procSendPkt)
}

func stmGetPacketBufRef() *[]byte {
	return stmPacketDataPool.Get().(*[]byte)
}

func stmPutPacketBufRef(bufRef *[]byte, buf []byte) {
	if bufRef == nil {
		return
	}
	*bufRef = buf[:0]
	stmPacketDataPool.Put(bufRef)
}
