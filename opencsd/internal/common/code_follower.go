package common

import (
	"encoding/binary"
	"errors"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
)

// CodeFollower follows the execution path by decoding instructions.
// It interfaces with memory access and instruction decode.
type CodeFollower struct {
	instrInfo    ocsd.InstrInfo
	memAccess    TargetMemAccess
	idDecode     InstrDecode
	startAddr    ocsd.VAddr
	endAddr      ocsd.VAddr
	nextAddr     ocsd.VAddr
	noAccessAddr ocsd.VAddr
	memSpace     ocsd.MemSpaceAcc
	traceID      uint8
	arch         ocsd.ArchProfile
	isa          ocsd.ISA
	hasNext      bool
	hasNaccErr   bool
	instructs    uint32
	valid        bool
}

// FollowResult contains the decoded single-atom follow outcome.
type FollowResult struct {
	HasNext   bool
	HasNacc   bool
	NaccAddr  ocsd.VAddr
	NumInstr  uint32
	RangeSt   ocsd.VAddr
	RangeEn   ocsd.VAddr
	NextAddr  ocsd.VAddr
	InstrInfo ocsd.InstrInfo
}

func (r FollowResult) HasRange() bool {
	return r.RangeSt < r.RangeEn
}

// NewCodeFollower creates a new CodeFollower.
func NewCodeFollower() *CodeFollower {
	cf := &CodeFollower{
		startAddr:    ocsd.VAddr(ocsd.VAMask),
		endAddr:      ocsd.VAddr(ocsd.VAMask),
		nextAddr:     ocsd.VAddr(ocsd.VAMask),
		noAccessAddr: ocsd.VAddr(ocsd.VAMask),
		hasNext:      false,
		hasNaccErr:   false,
		instructs:    0,
		valid:        false,
	}
	return cf
}

// NewCodeFollowerWithInterfaces creates a CodeFollower and attaches decoder interfaces.
func NewCodeFollowerWithInterfaces(memAccess TargetMemAccess, idDecode InstrDecode) *CodeFollower {
	cf := NewCodeFollower()
	cf.memAccess = memAccess
	cf.idDecode = idDecode
	// valid is computed lazily in FollowSingleAtom.
	return cf
}

// SetInterfaces updates the active memory and instruction decode interfaces.
func (cf *CodeFollower) SetInterfaces(memAccess TargetMemAccess, idDecode InstrDecode) {
	cf.memAccess = memAccess
	cf.idDecode = idDecode
}

func (cf *CodeFollower) SetArchProfile(arch ocsd.ArchProfile) {
	cf.arch = arch
	cf.instrInfo.PeType = arch
}

func (cf *CodeFollower) SetMemSpace(memSpace ocsd.MemSpaceAcc) {
	cf.memSpace = memSpace
}

func (cf *CodeFollower) SetTraceID(traceID uint8) {
	cf.traceID = traceID
}

func (cf *CodeFollower) SetISA(isa ocsd.ISA) {
	cf.isa = isa
	cf.instrInfo.ISA = isa
}

func (cf *CodeFollower) SetDSBDMBasWP() {
	cf.instrInfo.DsbDmbWaypoints = 1
}

func (cf *CodeFollower) InstrType() ocsd.InstrType {
	return cf.instrInfo.Type
}

func (cf *CodeFollower) InstrSubType() ocsd.InstrSubtype {
	return cf.instrInfo.Subtype
}

func (cf *CodeFollower) IsCondInstr() bool {
	return cf.instrInfo.IsConditional == 1
}

func (cf *CodeFollower) IsLink() bool {
	return cf.instrInfo.IsLink == 1
}

func (cf *CodeFollower) ISAChanged() bool {
	return cf.instrInfo.ISA != cf.instrInfo.NextISA
}

func (cf *CodeFollower) NextISA() ocsd.ISA {
	return cf.instrInfo.NextISA
}

func (cf *CodeFollower) InstrSize() uint8 {
	return cf.instrInfo.InstrSize
}

func (cf *CodeFollower) InstrInfo() *ocsd.InstrInfo {
	return &cf.instrInfo
}

func (cf *CodeFollower) MemSpace() ocsd.MemSpaceAcc {
	return cf.memSpace
}

// DecodeSingleOpCode decodes a single opcode at instrInfo.InstrAddr.
func (cf *CodeFollower) DecodeSingleOpCode() error {
	const bytesReq uint32 = 4

	// Read memory location for opcode
	readBytes, pData, err := cf.memAccess.ReadTargetMemory(cf.instrInfo.InstrAddr, cf.traceID, cf.memSpace, bytesReq)

	// Treat both ErrNoAccessor and too-short reads as memory unavailable
	if errors.Is(err, memacc.ErrNoAccessor) || (err == nil && readBytes < 4) {
		// Memory unavailable
		cf.hasNaccErr = true
		cf.noAccessAddr = cf.instrInfo.InstrAddr
		cf.hasNext = false
		cf.nextAddr = cf.instrInfo.InstrAddr
		return ocsd.ErrMemNacc
	}

	if err != nil {
		return err
	}

	if readBytes == 4 && len(pData) >= 4 {
		cf.instrInfo.Opcode = binary.LittleEndian.Uint32(pData[:4])

		err = cf.idDecode.DecodeInstruction(&cf.instrInfo)
		return err
	}

	// Defensive: should not reach here given the check above, but handle it
	cf.hasNaccErr = true
	cf.noAccessAddr = cf.instrInfo.InstrAddr
	cf.hasNext = false
	cf.nextAddr = cf.instrInfo.InstrAddr
	return ocsd.ErrMemNacc
}

func (cf *CodeFollower) resetFollowerState() bool {
	cf.hasNext = false
	cf.hasNaccErr = false
	cf.instructs = 0
	cf.endAddr = cf.startAddr
	cf.nextAddr = cf.startAddr
	cf.noAccessAddr = cf.startAddr

	cf.valid = cf.memAccess != nil && cf.idDecode != nil
	return cf.valid
}

// followSingleAtomInternal decodes an instruction at a single location and calculates the next address.
func (cf *CodeFollower) followSingleAtomInternal(addrStart ocsd.VAddr, atom ocsd.AtmVal) error {
	if !cf.resetFollowerState() {
		return ocsd.ErrNotInit
	}

	cf.endAddr = addrStart
	cf.startAddr = addrStart
	cf.instrInfo.InstrAddr = addrStart
	err := cf.DecodeSingleOpCode()

	if err != nil {
		if errors.Is(err, ocsd.ErrMemNacc) {
			cf.hasNaccErr = true
			cf.noAccessAddr = cf.instrInfo.InstrAddr
			cf.nextAddr = cf.instrInfo.InstrAddr
			cf.hasNext = false
		}
		return err
	}

	// Set end range - always after the instruction executed
	cf.endAddr = cf.instrInfo.InstrAddr + ocsd.VAddr(cf.instrInfo.InstrSize)
	cf.instructs = 1

	// Assume next addr is the instruction after
	cf.nextAddr = cf.endAddr
	cf.hasNext = true

	// Case when next address is different depending on branch and atom
	switch cf.instrInfo.Type {
	case ocsd.InstrBr:
		if atom == ocsd.AtomE { // Executed the direct branch
			cf.nextAddr = cf.instrInfo.BranchAddr
		}
	case ocsd.InstrBrIndirect:
		if atom == ocsd.AtomE { // Executed indirect branch
			cf.hasNext = false
		}
	}

	return nil
}

// FollowSingleAtom decodes an instruction and returns the result snapshot by value.
func (cf *CodeFollower) FollowSingleAtom(addrStart ocsd.VAddr, atom ocsd.AtmVal) (FollowResult, error) {
	err := cf.followSingleAtomInternal(addrStart, atom)
	return FollowResult{
		HasNext:   cf.hasNext,
		HasNacc:   cf.hasNaccErr,
		NaccAddr:  cf.noAccessAddr,
		NumInstr:  cf.instructs,
		RangeSt:   cf.startAddr,
		RangeEn:   cf.endAddr,
		NextAddr:  cf.nextAddr,
		InstrInfo: cf.instrInfo,
	}, err
}
