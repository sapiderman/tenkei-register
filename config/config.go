// Package config provides configuration management functionalities
package config

import (
	"errors"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

var (
	isInitialized = false
)

func IsInitialized() bool {
	return isInitialized
}

func SetInitialized(initialized bool) {
	isInitialized = initialized
}

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
}
type ServerConfig struct {
	Port              string `mapstructure:"port"`
	Mode              string `mapstructure:"mode"`
	ReadHeaderTimeout string `mapstructure:"read_header_timeout"`
	TurnstileSecret   string `mapstructure:"turnstile_secret_key"`
	TurnstileEnabled  bool   `mapstructure:"turnstile_enabled"`
	Version           string `mapstructure:"version"`
	XCFBypass         string `mapstructure:"x_cf_bypass"` // need to match with frontend config
}

type DatabaseConfig struct {
	ConnectionString string `mapstructure:"connection_string"`
}

func LoadConfig(path string) (*Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config") // Expects config.yaml, config.json, etc.
	viper.SetConfigType("yaml")   // Default format

	// 1. Set Defaults
	viper.SetDefault("server.port", 3000)
	viper.SetDefault("server.mode", "production")
	viper.SetDefault("server.read_header_timeout", "5s")
	viper.SetDefault("server.version", "0.0.3-20260606")
	viper.SetDefault("server.turnstile_enabled", true)

	// 2. Load Config File
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// Config file not found; ignore error if desired and rely on defaults/env vars
	}

	// 3. Configure Environment Variables
	// Allow mapping "database.host" to "TENKEI_DATABASE_HOST"
	viper.SetEnvPrefix("TENKEI")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv() // Read ENV variables

	// Explicitly bind well-known environment variables for robustness
	// Cloud Run needs the PORT variable, so bind it explicitly
	_ = viper.BindEnv("server.port", "PORT")

	_ = viper.BindEnv("server.turnstile_secret_key", "TENKEI_SERVER_TURNSTILE_SECRET_KEY")
	_ = viper.BindEnv("database.connection_string", "TENKEI_DATABASE_CONNECTION_STRING")
	_ = viper.BindEnv("server.x_cf_bypass", "TENKEI_SERVER_X_CF_BYPASS")
	_ = viper.BindEnv("server.mode", "TENKEI_SERVER_MODE")
	_ = viper.BindEnv("server.turnstile_enabled", "TENKEI_SERVER_TURNSTILE_ENABLED")

	// 4. Unmarshal into Struct
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// check turnstile secret is setup properly if turnstile is enabled
	if cfg.Server.TurnstileEnabled && cfg.Server.TurnstileSecret == "" {
		return nil, errors.New("server.turnstile_secret_key not configured, check environment ******************************************")
	}
	if cfg.Server.TurnstileEnabled {
		log.Info().Msg("Yaay Turnstile secret key is set")
	}

	if strings.TrimSpace(cfg.Database.ConnectionString) == "" {
		return nil, errors.New("database.connection_string not configured, check environment *******************************")
	}

	if strings.TrimSpace(cfg.Server.XCFBypass) == "" {
		return nil, errors.New("server.x_cf_bypass not configured, check environment ***************************************")
	}

	SetInitialized(true)
	return &cfg, nil
}
