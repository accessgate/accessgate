package config

import (
	"context"

	"github.com/accessgate/accessgate/internal/configload"
)

// Load reads config from optional file plus environment (same pipeline as the accessgate-auth binary),
// applies defaults, and validates.
func Load(ctx context.Context, configPath string) (*Config, error) {
	var cfg Config
	if err := configload.LoadInto(ctx, configPath, &cfg); err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
