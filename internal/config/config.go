package config

import (
	"fmt"
	"net"

	"perimeter-scanner/infrastructure/env"
	"perimeter-scanner/infrastructure/logger"
)

// Application holds daemon-level settings that control scan scheduling and parallelism.
type Application struct {
	ScanInterval int `yaml:"scan_interval" env:"SCAN_INTERVAL" env-default:"300"` // seconds between scans
	WorkerCount  int `yaml:"worker_count"  env:"WORKER_COUNT"  env-default:"10"`  // parallel enrichment workers
}

// Scanner holds settings passed directly to the network scanning stage.
type Scanner struct {
	BinaryPath string   `yaml:"binary_path" env:"SCAN_BINARY_PATH" env-default:"masscan"`      // path to masscan binary
	Rate       int      `yaml:"rate"        env:"SCAN_RATE"        env-default:"1000"`         // packets per second
	Interface  string   `yaml:"interface"   env:"SCAN_INTERFACE"   env-default:""`             // network interface; auto-detected if empty
	Targets    []string `yaml:"targets"     env:"SCAN_TARGETS"     env-delimiters:","`         // CIDRs or IPs to scan
	Ports      string   `yaml:"ports"       env:"SCAN_PORTS"       env-default:"80,8000-8100"` // masscan port spec
}

// Vulners holds credentials for the Vulners exploit-lookup API.
// If APIKey is empty, exploit detection is disabled.
type Vulners struct {
	APIKey string `yaml:"api_key" env:"VULNERS_API_KEY"`
}

// Database holds PostgreSQL connection parameters.
type Database struct {
	Host     string `yaml:"host"     env:"POSTGRES_HOST"     env-default:"localhost"`
	Port     int    `yaml:"port"     env:"POSTGRES_PORT"     env-default:"5432"`
	User     string `yaml:"user"     env:"POSTGRES_USER"     env-default:"postgres"`
	Password string `yaml:"password" env:"POSTGRES_PASSWORD" env-default:"password"`
	Name     string `yaml:"name"     env:"POSTGRES_DB"       env-default:"perimeter-scanner"`
	SSLMode  string `yaml:"sslmode"  env:"POSTGRES_SSLMODE"  env-default:"disable"`
}

// URL returns a PostgreSQL connection string built from the Database fields.
func (d Database) URL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User,
		d.Password,
		d.Host,
		d.Port,
		d.Name,
		d.SSLMode,
	)
}

// Telegram holds credentials for the Telegram Bot API alert notifier.
type Telegram struct {
	Token  string `yaml:"token"   env:"TELEGRAM_TOKEN"`
	ChatID string `yaml:"chat_id" env:"TELEGRAM_CHAT_ID"`
}

// Config is the root configuration structure for the application.
type Config struct {
	Application Application   `yaml:"application"`
	Scanner     Scanner       `yaml:"scanner"`
	Vulners     Vulners       `yaml:"vulners"`
	Logger      logger.Config `yaml:"logger"`
	Database    Database      `yaml:"database"`
	Telegram    Telegram      `yaml:"telegram"`
}

// MustLoad reads configuration from the YAML file at path, overrides values
// with environment variables, and auto-detects the network interface if one
// was not explicitly configured. Panics if the file cannot be read or parsed.
func MustLoad(path string) Config {
	var cfg Config
	env.MustLoad(path, &cfg)

	if cfg.Scanner.Interface == "" {
		cfg.Scanner.Interface = GetActiveInterface()
	}

	return cfg
}

// GetActiveInterface returns the name of the first network interface that is
// up, non-loopback, has a hardware (MAC) address, and has at least one IP
// address assigned. Falls back to "eth0" if no suitable interface is found.
func GetActiveInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			if len(iface.HardwareAddr) == 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			if len(addrs) > 0 {
				return iface.Name
			}
		}
	}
	return "eth0"
}
