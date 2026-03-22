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
	_ = reg.RegisterDecoderManagerByName(ocsd.BuiltinDcdSTM, &stm.DecoderManager{})
	_ = reg.RegisterDecoderManagerByName(ocsd.BuiltinDcdITM, &itm.DecoderManager{})
	_ = reg.RegisterDecoderManagerByName(ocsd.BuiltinDcdPTM, &ptm.DecoderManager{})
	_ = reg.RegisterDecoderManagerByName(ocsd.BuiltinDcdETMV3, etmv3.NewDecoderManager())
	_ = reg.RegisterDecoderManagerByName(ocsd.BuiltinDcdETMV4I, etmv4.NewDecoderManager())
	_ = reg.RegisterDecoderManagerByName(ocsd.BuiltinDcdETE, ete.NewDecoderManager())
}
