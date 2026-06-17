package config

import (
	"perimeter-scanner/infrastructure/env"
	"perimeter-scanner/infrastructure/logger"
)

type Scanner struct {
	Targets []string `yaml:"targets" env:"SCAN_TARGETS" env-delimiters:","`
	Ports   string   `yaml:"ports"   env:"SCAN_PORTS"   env-default:"80,8000-8100"`
	Rate    int      `yaml:"rate"    env:"SCAN_RATE"    env-default:"1000"`
}

type Config struct {
	Scanner Scanner       `yaml:"scanner"`
	Logger  logger.Config `yaml:"logger"`
}

func MustLoad(path string) Config {
	var cfg Config
	env.MustLoad(path, &cfg)
	return cfg
}
