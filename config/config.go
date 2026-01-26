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

func init() {

}
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
	viper.SetDefault("server.mode", "development")
	viper.SetDefault("server.read_header_timeout", "5s")

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
	viper.BindEnv("server.port", "PORT")

	viper.BindEnv("server.turnstile_secret_key", "TURNSTILE_SECRET_KEY", "TENKEI_TURNSTILE_SECRET_KEY")
	viper.BindEnv("database.connection_string", "DATABASE_CONNECTION_STRING", "TENKEI_DATABASE_CONNECTION_STRING")

	// 4. Unmarshal into Struct
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// check turnstile secret is setup properly
	if cfg.Server.TurnstileSecret == "" {
		return nil, errors.New("TURNSTILE_SECRET_KEY not configured ******************************************")
	} else {
		log.Info().Msg("Yaay Turnstile secret key is set")
	}

	if strings.TrimSpace(cfg.Database.ConnectionString) == "" {
		return nil, errors.New("database connection string not configured *******************************")
	}
	return &cfg, nil
}
