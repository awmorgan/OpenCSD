package common

import "opencsd/internal/ocsd"

// CodeFollower follows the execution path by decoding instructions.
// It interfaces with memory access and instruction decode.
// memAccess and idDecode are pointers to the decoder's live attachment points,
// so subsequent Attach calls on the decoder are immediately visible here.
type CodeFollower struct {
	instrInfo ocsd.InstrInfo
	memAccess *AttachPt[TargetMemAccess]
	idDecode  *AttachPt[InstrDecode]
	stAddr    ocsd.VAddr
	enAddr    ocsd.VAddr
	nextAddr  ocsd.VAddr
	memSpace  ocsd.MemSpaceAcc
	csTraceID uint8
	arch      ocsd.ArchProfile
	isa       ocsd.ISA
	bHasNxt   bool
	naccErr   bool
	instructs uint32
	valid     bool
}

// NewCodeFollower creates a new CodeFollower.
func NewCodeFollower() *CodeFollower {
	cf := &CodeFollower{
		stAddr:    ocsd.VAddr(ocsd.VAMask),
		enAddr:    ocsd.VAddr(ocsd.VAMask),
		nextAddr:  ocsd.VAddr(ocsd.VAMask),
		bHasNxt:   false,
		naccErr:   false,
		instructs: 0,
		valid:     false,
	}
	return cf
}

func (cf *CodeFollower) InitInterfaces(memAccess *AttachPt[TargetMemAccess], idDecode *AttachPt[InstrDecode]) {
	cf.memAccess = memAccess
	cf.idDecode = idDecode
	// valid is computed lazily in FollowSingleInstr so newly-attached mocks are seen
}

func (cf *CodeFollower) SetArchProfile(arch ocsd.ArchProfile) {
	cf.arch = arch
	cf.instrInfo.PeType = arch
}

func (cf *CodeFollower) SetMemSpace(memSpace ocsd.MemSpaceAcc) {
	cf.memSpace = memSpace
}

func (cf *CodeFollower) SetTraceID(csTraceID uint8) {
	cf.csTraceID = csTraceID
}

func (cf *CodeFollower) SetISA(isa ocsd.ISA) {
	cf.isa = isa
	cf.instrInfo.Isa = isa
}

func (cf *CodeFollower) HasNextInstr() bool {
	return cf.bHasNxt
}

func (cf *CodeFollower) HasNextAddr() bool {
	return cf.bHasNxt
}

func (cf *CodeFollower) IsNaccErr() bool {
	return cf.naccErr
}

func (cf *CodeFollower) HasError() bool {
	return cf.naccErr
}

func (cf *CodeFollower) ClearError() {
	cf.naccErr = false
}

func (cf *CodeFollower) GetNextAddr() ocsd.VAddr {
	return cf.nextAddr
}

func (cf *CodeFollower) GetNumInstructs() uint32 {
	return cf.instructs
}

func (cf *CodeFollower) GetInstrInfo() *ocsd.InstrInfo {
	return &cf.instrInfo
}

func (cf *CodeFollower) RangeSt() ocsd.VAddr {
	return cf.stAddr
}

func (cf *CodeFollower) RangeEn() ocsd.VAddr {
	return cf.enAddr
}

// DecodeSingleOpCode decodes a single opcode at instrInfo.InstrAddr.
func (cf *CodeFollower) DecodeSingleOpCode() ocsd.Err {
	var bytesReq uint32 = 4

	// Read memory location for opcode
	readBytes, pData, err := cf.memAccess.First().ReadTargetMemory(cf.instrInfo.InstrAddr, cf.csTraceID, cf.memSpace, bytesReq)

	if err != ocsd.OK {
		return err
	}

	if readBytes == 4 && len(pData) >= 4 {
		cf.instrInfo.Opcode = 0
		for i := range 4 {
			cf.instrInfo.Opcode |= uint32(pData[i]) << (i * 8)
		}

		err = cf.idDecode.First().DecodeInstruction(&cf.instrInfo)
		return err
	}

	// Memory unavailable
	cf.naccErr = true
	cf.nextAddr = cf.instrInfo.InstrAddr
	return ocsd.ErrMemNacc
}

func (cf *CodeFollower) initFollowerState() bool {
	cf.bHasNxt = false
	cf.naccErr = false
	cf.enAddr = cf.stAddr
	cf.nextAddr = cf.stAddr

	cf.valid = cf.memAccess != nil && cf.idDecode != nil &&
		cf.memAccess.HasAttachedAndEnabled() && cf.idDecode.HasAttachedAndEnabled()
	return cf.valid
}

// FollowSingleAtom decodes an instruction at a single location and calculates the next address.
func (cf *CodeFollower) FollowSingleAtom(addrStart ocsd.VAddr, atom ocsd.AtmVal) ocsd.Err {
	if !cf.initFollowerState() {
		return ocsd.ErrNotInit
	}

	cf.enAddr = addrStart
	cf.stAddr = addrStart
	cf.instrInfo.InstrAddr = addrStart
	err := cf.DecodeSingleOpCode()

	if err != ocsd.OK {
		cf.naccErr = err == ocsd.ErrMemNacc
		return err
	}

	// Set end range - always after the instruction executed
	cf.enAddr = cf.instrInfo.InstrAddr + ocsd.VAddr(cf.instrInfo.InstrSize)
	cf.instructs = 1

	// Assume next addr is the instruction after
	cf.nextAddr = cf.enAddr
	cf.bHasNxt = true

	// Case when next address is different depending on branch and atom
	switch cf.instrInfo.Type {
	case ocsd.InstrBr:
		if atom == ocsd.AtomE { // Executed the direct branch
			cf.nextAddr = cf.instrInfo.BranchAddr
		}
	case ocsd.InstrBrIndirect:
		if atom == ocsd.AtomE { // Executed indirect branch
			cf.bHasNxt = false
		}
	}

	return ocsd.OK
}
