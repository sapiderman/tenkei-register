package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// resetViper restores viper's global state between tests. viper is a package
// singleton, so every test must reset it and the isInitialized flag.
func resetViper(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		viper.Reset()
		SetInitialized(false)
	})
}

// hideEnv blanks every TENKEI_* and PORT var so ambient shell values cannot
// leak into LoadConfig. A bound env var that is present-but-empty resolves to
// the empty string (suppressing the viper default), so every test must
// explicitly set the values it actually depends on.
func hideEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PORT",
		"TENKEI_SERVER_PORT",
		"TENKEI_SERVER_MODE",
		"TENKEI_SERVER_READ_HEADER_TIMEOUT",
		"TENKEI_SERVER_TURNSTILE_SECRET_KEY",
		"TENKEI_SERVER_TURNSTILE_ENABLED",
		"TENKEI_SERVER_X_CF_BYPASS",
		"TENKEI_DATABASE_CONNECTION_STRING",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	t.Setenv("TENKEI_SERVER_TURNSTILE_ENABLED", "false")
	t.Setenv("TENKEI_DATABASE_CONNECTION_STRING", "postgres://user:pass@host/db")
	t.Setenv("TENKEI_SERVER_X_CF_BYPASS", "test-key")

	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.Port != "3000" {
		t.Errorf("port: got %q, want %q", cfg.Server.Port, "3000")
	}
	if cfg.Server.Mode != "production" {
		t.Errorf("mode: got %q, want %q", cfg.Server.Mode, "production")
	}
	if cfg.Server.ReadHeaderTimeout != "5s" {
		t.Errorf("read_header_timeout: got %q, want %q", cfg.Server.ReadHeaderTimeout, "5s")
	}
	if cfg.Server.TurnstileEnabled {
		t.Error("turnstile_enabled: expected false (env override)")
	}
	if cfg.Database.ConnectionString != "postgres://user:pass@host/db" {
		t.Errorf("connection_string: got %q", cfg.Database.ConnectionString)
	}
	if cfg.Server.XCFBypass != "test-key" {
		t.Errorf("x_cf_bypass: got %q", cfg.Server.XCFBypass)
	}
	if !IsInitialized() {
		t.Error("expected IsInitialized() == true after successful load")
	}
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	t.Setenv("PORT", "8080")
	t.Setenv("TENKEI_SERVER_MODE", "development")
	t.Setenv("TENKEI_SERVER_READ_HEADER_TIMEOUT", "3s")
	t.Setenv("TENKEI_SERVER_TURNSTILE_ENABLED", "false")
	t.Setenv("TENKEI_DATABASE_CONNECTION_STRING", "postgres://env/db")
	t.Setenv("TENKEI_SERVER_X_CF_BYPASS", "env-key")

	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.Port != "8080" {
		t.Errorf("port: got %q, want %q", cfg.Server.Port, "8080")
	}
	if cfg.Server.Mode != "development" {
		t.Errorf("mode: got %q, want %q", cfg.Server.Mode, "development")
	}
	if cfg.Server.ReadHeaderTimeout != "3s" {
		t.Errorf("read_header_timeout: got %q, want %q", cfg.Server.ReadHeaderTimeout, "3s")
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	dir := t.TempDir()
	file := `server:
  port: 9090
  mode: staging
  read_header_timeout: 7s
  turnstile_enabled: false
  x_cf_bypass: file-key
database:
  connection_string: postgres://file/db
`
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(file), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.Port != "9090" {
		t.Errorf("port: got %q, want %q", cfg.Server.Port, "9090")
	}
	if cfg.Server.Mode != "staging" {
		t.Errorf("mode: got %q, want %q", cfg.Server.Mode, "staging")
	}
	if cfg.Server.ReadHeaderTimeout != "7s" {
		t.Errorf("read_header_timeout: got %q, want %q", cfg.Server.ReadHeaderTimeout, "7s")
	}
	if cfg.Database.ConnectionString != "postgres://file/db" {
		t.Errorf("connection_string: got %q", cfg.Database.ConnectionString)
	}
	if cfg.Server.XCFBypass != "file-key" {
		t.Errorf("x_cf_bypass: got %q", cfg.Server.XCFBypass)
	}
}

func TestLoadConfig_SuccessWithTurnstileSecret(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	t.Setenv("TENKEI_SERVER_TURNSTILE_ENABLED", "true")
	t.Setenv("TENKEI_SERVER_TURNSTILE_SECRET_KEY", "secret")
	t.Setenv("TENKEI_DATABASE_CONNECTION_STRING", "postgres://user:pass@host/db")
	t.Setenv("TENKEI_SERVER_X_CF_BYPASS", "test-key")

	if _, err := LoadConfig(t.TempDir()); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
}

func TestLoadConfig_MissingTurnstileSecret(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	// turnstile_enabled defaults to true; no secret configured.
	t.Setenv("TENKEI_DATABASE_CONNECTION_STRING", "postgres://user:pass@host/db")
	t.Setenv("TENKEI_SERVER_X_CF_BYPASS", "test-key")

	_, err := LoadConfig(t.TempDir())
	if err == nil {
		t.Fatal("expected error when turnstile enabled without secret")
	}
	if !strings.Contains(err.Error(), "turnstile_secret_key") {
		t.Errorf("error should mention turnstile_secret_key, got: %v", err)
	}
}

func TestLoadConfig_MissingDatabaseConnection(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	t.Setenv("TENKEI_SERVER_TURNSTILE_ENABLED", "false")
	t.Setenv("TENKEI_SERVER_X_CF_BYPASS", "test-key")

	_, err := LoadConfig(t.TempDir())
	if err == nil {
		t.Fatal("expected error when database connection string is missing")
	}
	if !strings.Contains(err.Error(), "connection_string") {
		t.Errorf("error should mention connection_string, got: %v", err)
	}
}

func TestLoadConfig_MissingXCFBypass(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	t.Setenv("TENKEI_SERVER_TURNSTILE_ENABLED", "false")
	t.Setenv("TENKEI_DATABASE_CONNECTION_STRING", "postgres://user:pass@host/db")

	_, err := LoadConfig(t.TempDir())
	if err == nil {
		t.Fatal("expected error when x_cf_bypass is missing")
	}
	if !strings.Contains(err.Error(), "x_cf_bypass") {
		t.Errorf("error should mention x_cf_bypass, got: %v", err)
	}
}

func TestLoadConfig_InvalidConfigFile(t *testing.T) {
	resetViper(t)
	hideEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("not: [valid"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := LoadConfig(dir); err == nil {
		t.Fatal("expected error for invalid config file")
	}
}

func TestIsInitialized(t *testing.T) {
	SetInitialized(false)
	if IsInitialized() {
		t.Error("expected false after SetInitialized(false)")
	}
	SetInitialized(true)
	if !IsInitialized() {
		t.Error("expected true after SetInitialized(true)")
	}
	SetInitialized(false)
}
