package ete

import (
	"io"

	"opencsd/internal/etmv4"
)

func NewProcessor(config *Config, reader ...io.Reader) *etmv4.Processor {
	if config == nil {
		cfg := NewConfig()
		return etmv4.NewProcessor(cfg.ToETMv4Config(), reader...)
	}
	return etmv4.NewProcessor(config.ToETMv4Config(), reader...)
}
