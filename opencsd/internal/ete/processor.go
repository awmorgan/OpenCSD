package ete

import "opencsd/internal/etmv4"

type Processor = etmv4.Processor

func NewProcessor(config *Config) *Processor {
	if config == nil {
		cfg := NewConfig()
		return etmv4.NewProcessor(cfg.ToETMv4Config())
	}
	return etmv4.NewProcessor(config.ToETMv4Config())
}
