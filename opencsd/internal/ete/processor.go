package ete

import "opencsd/internal/etmv4"

func NewProcessor(config *Config) *etmv4.Processor {
	if config == nil {
		cfg := NewConfig()
		return etmv4.NewProcessor(cfg.ToETMv4Config())
	}
	return etmv4.NewProcessor(config.ToETMv4Config())
}
