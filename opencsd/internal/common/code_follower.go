package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"opencsd/internal/memacc"
	"opencsd/internal/ocsd"
)

// CodeFollower follows the execution path by decoding instructions.
// It interfaces with memory access and instruction decode.
type CodeFollower struct {
	InstrInfo    ocsd.InstrInfo
	MemAccess    TargetMemAccess
	IdDecode     InstrDecode
	StartAddr    ocsd.VAddr
	EndAddr      ocsd.VAddr
	NextAddr     ocsd.VAddr
	NoAccessAddr ocsd.VAddr
	MemSpace     ocsd.MemSpaceAcc
	TraceID      uint8
	Arch         ocsd.ArchProfile
	Isa          ocsd.ISA
	HasNext      bool
	HasNaccErr   bool
	Instructs    uint32
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

// NewCodeFollowerWithInterfaces creates a CodeFollower and attaches required decoder interfaces.

// Both memAccess and idDecode must be non-nil.
func NewCodeFollowerWithInterfaces(memAccess TargetMemAccess, idDecode InstrDecode) (*CodeFollower, error) {
	if memAccess == nil {
		return nil, fmt.Errorf("%w: code follower mem access cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if idDecode == nil {
		return nil, fmt.Errorf("%w: code follower instruction decoder cannot be nil", ocsd.ErrInvalidParamVal)
	}

	cf := &CodeFollower{
		MemAccess:    memAccess,
		IdDecode:     idDecode,
		StartAddr:    ocsd.VAddr(ocsd.VAMask),
		EndAddr:      ocsd.VAddr(ocsd.VAMask),
		NextAddr:     ocsd.VAddr(ocsd.VAMask),
		NoAccessAddr: ocsd.VAddr(ocsd.VAMask),
		HasNext:      false,
		HasNaccErr:   false,
		Instructs:    0,
	}
	return cf, nil
}

// SetInterfaces updates the active memory and instruction decode interfaces.
func (cf *CodeFollower) SetInterfaces(memAccess TargetMemAccess, idDecode InstrDecode) error {
	if memAccess == nil {
		return fmt.Errorf("%w: code follower mem access cannot be nil", ocsd.ErrInvalidParamVal)
	}
	if idDecode == nil {
		return fmt.Errorf("%w: code follower instruction decoder cannot be nil", ocsd.ErrInvalidParamVal)
	}
	cf.MemAccess = memAccess
	cf.IdDecode = idDecode
	return nil
}

func (cf *CodeFollower) SetDSBDMBasWP() {
	cf.InstrInfo.DsbDmbWaypoints = 1
}

// DecodeSingleOpCode decodes a single opcode at instrInfo.InstrAddr.
func (cf *CodeFollower) DecodeSingleOpCode() error {
	const bytesReq uint32 = 4

	// Read memory location for opcode
	readBytes, pData, err := cf.MemAccess.ReadTargetMemory(cf.InstrInfo.InstrAddr, cf.TraceID, cf.MemSpace, bytesReq)

	// Treat no-access and incomplete opcode reads as memory unavailable.
	if errors.Is(err, memacc.ErrNoAccessor) || (err == nil && (readBytes != bytesReq || len(pData) < int(bytesReq))) {
		// Memory unavailable
		cf.HasNaccErr = true
		cf.NoAccessAddr = cf.InstrInfo.InstrAddr
		cf.HasNext = false
		cf.NextAddr = cf.InstrInfo.InstrAddr
		return ocsd.ErrMemNacc
	}

	if err != nil {
		return err
	}

	cf.InstrInfo.Opcode = binary.LittleEndian.Uint32(pData[:4])

	err = cf.IdDecode.DecodeInstruction(&cf.InstrInfo)
	return err
}

func (cf *CodeFollower) resetFollowerState() {
	cf.HasNext = false
	cf.HasNaccErr = false
	cf.Instructs = 0
	cf.EndAddr = cf.StartAddr
	cf.NextAddr = cf.StartAddr
	cf.NoAccessAddr = cf.StartAddr
}

// followSingleAtomInternal decodes an instruction at a single location and calculates the next address.
func (cf *CodeFollower) followSingleAtomInternal(addrStart ocsd.VAddr, atom ocsd.AtmVal) error {
	cf.resetFollowerState()

	cf.EndAddr = addrStart
	cf.StartAddr = addrStart
	cf.InstrInfo.InstrAddr = addrStart
	err := cf.DecodeSingleOpCode()

	if err != nil {
		if errors.Is(err, ocsd.ErrMemNacc) {
			cf.HasNaccErr = true
			cf.NoAccessAddr = cf.InstrInfo.InstrAddr
			cf.NextAddr = cf.InstrInfo.InstrAddr
			cf.HasNext = false
		}
		return err
	}

	// Set end range - always after the instruction executed
	cf.EndAddr = cf.InstrInfo.InstrAddr + ocsd.VAddr(cf.InstrInfo.InstrSize)
	cf.Instructs = 1

	// Assume next addr is the instruction after
	cf.NextAddr = cf.EndAddr
	cf.HasNext = true

	// Case when next address is different depending on branch and atom
	switch cf.InstrInfo.Type {
	case ocsd.InstrBr:
		if atom == ocsd.AtomE { // Executed the direct branch
			cf.NextAddr = cf.InstrInfo.BranchAddr
		}
	case ocsd.InstrBrIndirect:
		if atom == ocsd.AtomE { // Executed indirect branch
			cf.HasNext = false
		}
	}

	return nil
}

// FollowSingleAtom decodes an instruction and returns the result snapshot by value.
func (cf *CodeFollower) FollowSingleAtom(addrStart ocsd.VAddr, atom ocsd.AtmVal) (FollowResult, error) {
	err := cf.followSingleAtomInternal(addrStart, atom)
	return FollowResult{
		HasNext:   cf.HasNext,
		HasNacc:   cf.HasNaccErr,
		NaccAddr:  cf.NoAccessAddr,
		NumInstr:  cf.Instructs,
		RangeSt:   cf.StartAddr,
		RangeEn:   cf.EndAddr,
		NextAddr:  cf.NextAddr,
		InstrInfo: cf.InstrInfo,
	}, err
}
