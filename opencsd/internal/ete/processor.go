package ete

import (
	"io"

	"opencsd/internal/etmv4"
)

func NewProcessor(config *Config, reader ...io.Reader) *etmv4.Processor {
	return etmv4.NewProcessor(etmv4Config(config), reader...)
}

func etmv4Config(config *Config) *etmv4.Config {
	if config == nil {
		config = NewConfig()
	}
	return config.ToETMv4Config()
}
