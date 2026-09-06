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
	Mailer   MailerConfig   `mapstructure:"mailer"`
}
type ServerConfig struct {
	Port              string `mapstructure:"port"`
	Mode              string `mapstructure:"mode"`
	ReadHeaderTimeout string `mapstructure:"read_header_timeout"`
	TurnstileSecret   string `mapstructure:"turnstile_secret_key"`
	TurnstileEnabled  bool   `mapstructure:"turnstile_enabled"`
	Version           string `mapstructure:"version"`
	LogLevel          string `mapstructure:"log_level"`
	XCFBypass         string `mapstructure:"x_cf_bypass"` // need to match with frontend config
	AppURL            string `mapstructure:"app_url"`     // web base URL used in reset-password email links
}

type DatabaseConfig struct {
	ConnectionString string `mapstructure:"connection_string"`
}

// MailerConfig holds the Resend email settings. Enabled is a plain flag so
// notifications can be toggled without touching the API key secret (same
// split as turnstile_enabled / turnstile_secret_key).
type MailerConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	ResendAPIKey string `mapstructure:"resend_api_key"`
	From         string `mapstructure:"from"`
	NotifyEmail  string `mapstructure:"notify_email"`
}

func LoadConfig(path string) (*Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config") // Expects config.yaml, config.json, etc.
	viper.SetConfigType("yaml")   // Default format

	// 1. Set Defaults
	viper.SetDefault("server.port", 3000)
	viper.SetDefault("server.mode", "production")
	viper.SetDefault("server.read_header_timeout", "5s")
	viper.SetDefault("server.version", "0.0.11-20260906")
	viper.SetDefault("server.turnstile_enabled", true)
	// zerolog's default global level is Debug, which logs every SQL statement
	// in production (queryHook logs at Debug). Default the app to info.
	viper.SetDefault("server.log_level", "info")
	viper.SetDefault("server.app_url", "https://www.tenkeiaikidojo.org")
	viper.SetDefault("mailer.enabled", true)
	viper.SetDefault("mailer.from", "Tenkei <no-reply@tenkeiaikidojo.org>")
	viper.SetDefault("mailer.notify_email", "info@tenkeiaikidojo.org")

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
	_ = viper.BindEnv("server.log_level", "TENKEI_SERVER_LOG_LEVEL")
	_ = viper.BindEnv("server.app_url", "TENKEI_SERVER_APP_URL")
	_ = viper.BindEnv("mailer.resend_api_key", "TENKEI_RESEND_API_KEY")
	_ = viper.BindEnv("mailer.enabled", "TENKEI_MAILER_ENABLED")
	_ = viper.BindEnv("mailer.from", "TENKEI_MAILER_FROM")
	_ = viper.BindEnv("mailer.notify_email", "TENKEI_MAILER_NOTIFY_EMAIL")

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

	// Mailer: fail fast in production when enabled without a key — a silent
	// no-mail production is worse than a refused boot. Outside production the
	// mailer degrades to a log-rendering implementation (see internal/mailer).
	if cfg.Mailer.Enabled && strings.TrimSpace(cfg.Mailer.ResendAPIKey) == "" {
		if cfg.Server.Mode == "production" {
			return nil, errors.New("mailer.resend_api_key not configured (TENKEI_RESEND_API_KEY) — refusing to start with mail enabled **************************")
		}
		log.Warn().Msg("mailer enabled but TENKEI_RESEND_API_KEY not set — emails will render to logs, not send")
	}

	SetInitialized(true)
	return &cfg, nil
}
