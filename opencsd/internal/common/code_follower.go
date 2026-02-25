package common

import "opencsd/internal/ocsd"

// CodeFollower follows the execution path by decoding instructions.
// It interfaces with memory access and instruction decode.
type CodeFollower struct {
	instrInfo ocsd.InstrInfo
	memAccess AttachPt[TargetMemAccess]
	idDecode  AttachPt[InstrDecode]
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
	cf.memAccess.SetEnabled(true)
	cf.idDecode.SetEnabled(true)
	return cf
}

func (cf *CodeFollower) InitInterfaces(memAccess *AttachPt[TargetMemAccess], idDecode *AttachPt[InstrDecode]) {
	cf.memAccess = *memAccess
	cf.idDecode = *idDecode
	cf.valid = false
	if cf.memAccess.HasAttachedAndEnabled() && cf.idDecode.HasAttachedAndEnabled() {
		cf.valid = true
	}
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

// FollowSingleInstr follows execution from the address for one instruction.
func (cf *CodeFollower) FollowSingleInstr(addr ocsd.VAddr) ocsd.Err {
	cf.stAddr = addr
	cf.enAddr = addr
	cf.nextAddr = addr
	cf.bHasNxt = false
	cf.naccErr = false
	cf.instructs = 0

	if !cf.valid {
		return ocsd.ErrNotInit
	}

	cf.instrInfo.InstrAddr = addr
	var bytesReq uint32 = 4
	if cf.isa == ocsd.ISAThumb2 {
		bytesReq = 2
	}

	readBytes, pData, err := cf.memAccess.First().ReadTargetMemory(addr, cf.csTraceID, cf.memSpace, bytesReq)
	if err != ocsd.OK || readBytes < bytesReq || len(pData) < int(bytesReq) {
		cf.naccErr = true
		return ocsd.ErrMemNacc
	}

	cf.instrInfo.Opcode = 0
	for i := 0; i < int(bytesReq); i++ {
		cf.instrInfo.Opcode |= uint32(pData[i]) << (i * 8)
	}

	// Pre-check for 32-bit thumb format
	if cf.isa == ocsd.ISAThumb2 && (cf.instrInfo.Opcode&0xE000) == 0xE000 && (cf.instrInfo.Opcode&0x1800) != 0 {
		// Needs another 2 bytes
		readBytes, pData2, err2 := cf.memAccess.First().ReadTargetMemory(addr+2, cf.csTraceID, cf.memSpace, 2)
		if err2 != ocsd.OK || readBytes < 2 || len(pData2) < 2 {
			cf.naccErr = true
			return ocsd.ErrMemNacc
		}
		cf.instrInfo.Opcode |= uint32(pData2[0]) << 16
		cf.instrInfo.Opcode |= uint32(pData2[1]) << 24
	}

	err = cf.idDecode.First().DecodeInstruction(&cf.instrInfo)
	if err != ocsd.OK {
		return err
	}

	cf.instructs = 1
	cf.enAddr = addr + ocsd.VAddr(cf.instrInfo.InstrSize)

	if cf.instrInfo.Type != ocsd.InstrOther {
		cf.nextAddr = cf.instrInfo.BranchAddr
	} else {
		cf.nextAddr = cf.enAddr
	}

	cf.bHasNxt = true
	return ocsd.OK
}
