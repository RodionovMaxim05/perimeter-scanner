package main

import (
	"flag"

	"perimeter-scanner/infrastructure/logger"
	"perimeter-scanner/internal/config"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "server configuration file")
	flag.Parse()

	cfg := config.MustLoad(configPath)

	log := logger.MustMakeLogger(cfg.Logger.LogLevel)

	log.Info("Application started successfully", "rate", cfg.Scanner.Rate)
	log.Debug("Target networks loaded", "targets", cfg.Scanner.Targets)
}
