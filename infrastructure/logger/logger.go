package logger

import (
	"log/slog"
	"os"
)

// Config holds logger settings loaded from YAML or environment variables.
type Config struct {
	LogLevel string `yaml:"log_level" default:"DEBUG"` // DEBUG, INFO, or ERROR
}

// MustMakeLogger constructs a text-format slog.Logger writing to stderr
// at the given log level. Panics if logLevel is not one of DEBUG, INFO, ERROR.
func MustMakeLogger(logLevel string) *slog.Logger {
	var level slog.Level
	switch logLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "ERROR":
		level = slog.LevelError
	default:
		panic("unknown log level: " + logLevel)
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}
