// Package config provides configuration management functionalities
package config

import (
	"strings"

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

	viper.SetDefault("database.connection_string", "postgres://user:password@localhost:5432/tenkei?sslmode=disable")

	// 2. Load Config File
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// Config file not found; ignore error if desired and rely on defaults/env vars
	}

	// 3. Configure Environment Variables
	viper.AutomaticEnv() // Read ENV variables

	// Allow mapping "database.host" to "TENKEI_DATABASE_HOST"
	viper.SetEnvPrefix("TENKEI")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Cloud Run needs the PORT variable, so bind it explicitly
	viper.BindEnv("server.port", "PORT")

	// 4. Unmarshal into Struct
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
