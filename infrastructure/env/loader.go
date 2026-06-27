package env

import (
	"log"

	"github.com/ilyakaznacheev/cleanenv"
)

// MustLoad reads configuration from the YAML file at path into cfg,
// then overrides any fields that have corresponding environment variables set.
// Panics via log.Fatalf if either step fails.
func MustLoad(path string, cfg interface{}) {
	if err := cleanenv.ReadConfig(path, cfg); err != nil {
		log.Fatalf("cannot read config: %v", err)
	}

	if err := cleanenv.ReadEnv(cfg); err != nil {
		log.Fatalf("cannot read env: %v", err)
	}
}
