package dcdtree

import (
	"opencsd/internal/etmv3"
	"opencsd/internal/itm"
	"opencsd/internal/ocsd"
	"opencsd/internal/ptm"
	"opencsd/internal/stm"
)

// init runs on package load to register standard decoders.
func init() {
	reg := GetDecoderRegister()
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdSTM, stm.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdITM, itm.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdPTM, ptm.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdETMV3, etmv3.NewDecoderManager())
	// ETE, ETMv4 can be added here later once ported.
}
