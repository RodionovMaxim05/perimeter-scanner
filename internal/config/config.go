package config

import (
	"fmt"
	"net"

	"perimeter-scanner/infrastructure/env"
	"perimeter-scanner/infrastructure/logger"
)

type Application struct {
	ScanInterval int `yaml:"scan_interval" env:"SCAN_INTERVAL" env-default:"300"`
	WorkerCount  int `yaml:"worker_count" env:"WORKER_COUNT" env-default:"10"`
}

type Scanner struct {
	BinaryPath string   `yaml:"binary_path" env:"SCAN_BINARY_PATH" env-default:"masscan"`
	Rate       int      `yaml:"rate"    env:"SCAN_RATE"    env-default:"1000"`
	Interface  string   `yaml:"interface" env:"SCAN_INTERFACE" env-default:""`
	Targets    []string `yaml:"targets" env:"SCAN_TARGETS" env-delimiters:","`
	Ports      string   `yaml:"ports"   env:"SCAN_PORTS"   env-default:"80,8000-8100"`
}

type Vulners struct {
	APIKey string `yaml:"api_key" env:"VULNERS_API_KEY"`
}

type Database struct {
	Host     string `yaml:"host" env:"POSTGRES_HOST" env-default:"localhost"`
	Port     int    `yaml:"port" env:"POSTGRES_PORT" env-default:"5432"`
	User     string `yaml:"user" env:"POSTGRES_USER" env-default:"postgres"`
	Password string `yaml:"password" env:"POSTGRES_PASSWORD" env-default:"password"`
	Name     string `yaml:"name" env:"POSTGRES_DB" env-default:"perimeter-scanner"`
	SSLMode  string `yaml:"sslmode" env:"POSTGRES_SSLMODE" env-default:"disable"`
}

type Telegram struct {
	Token  string `yaml:"token" env:"TELEGRAM_TOKEN"`
	ChatID string `yaml:"chat_id" env:"TELEGRAM_CHAT_ID"`
}

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

type Config struct {
	Application Application   `yaml:"application"`
	Scanner     Scanner       `yaml:"scanner"`
	Vulners     Vulners       `yaml:"vulners"`
	Logger      logger.Config `yaml:"logger"`
	Database    Database      `yaml:"database"`
	Telegram    Telegram      `yaml:"telegram"`
}

func MustLoad(path string) Config {
	var cfg Config
	env.MustLoad(path, &cfg)

	if cfg.Scanner.Interface == "" {
		cfg.Scanner.Interface = GetActiveInterface()
	}

	return cfg
}

func GetActiveInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		// Fall back to default if the OS has denied access to interfaces
		return "eth0"
	}

	for _, iface := range ifaces {
		// Look for an interface that is UP and is not the loopback
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			// Checking for the presence of a MAC address
			if len(iface.HardwareAddr) == 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			// If the interface has at least one IP address assigned
			if len(addrs) > 0 {
				return iface.Name
			}
		}
	}
	return "eth0"
}
