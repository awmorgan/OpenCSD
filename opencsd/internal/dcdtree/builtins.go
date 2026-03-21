package dcdtree

import (
	"opencsd/internal/ete"
	"opencsd/internal/etmv3"
	"opencsd/internal/etmv4"
	"opencsd/internal/itm"
	"opencsd/internal/ocsd"
	"opencsd/internal/ptm"
	"opencsd/internal/stm"
)

func registerBuiltinDecoders(reg *DecoderRegister) {
	if reg == nil {
		return
	}
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdSTM, stm.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdITM, itm.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdPTM, ptm.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdETMV3, etmv3.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdETMV4I, etmv4.NewDecoderManager())
	_ = reg.RegisterDecoderTypeByName(ocsd.BuiltinDcdETE, ete.NewDecoderManager())
}
