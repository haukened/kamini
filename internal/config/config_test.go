package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	koanf "github.com/knadh/koanf/v2"
)

// helper to write a temporary YAML config file
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	fp := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(fp, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}
	return fp
}

func TestLoad_DefaultsOnly(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Addr != DEFAULT_CONFIG.Server.Addr {
		t.Fatalf("Server.Addr = %q, want %q", cfg.Server.Addr, DEFAULT_CONFIG.Server.Addr)
	}
	if cfg.Log.Format != DEFAULT_CONFIG.Log.Format {
		t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, DEFAULT_CONFIG.Log.Format)
	}
}

func TestLoad_FileOverrides(t *testing.T) {
	y := `
server:
  addr: ":9999"
log:
  level: "debug"
storage:
  serial:
    file_path: "/tmp/serial.db"
authorize:
  principal_templates: ["a", "b"]
`
	fp := writeTempYAML(t, y)

	cfg, err := Load(fp)
	if err != nil {
		t.Fatalf("Load(file) error: %v", err)
	}
	if cfg.Server.Addr != ":9999" {
		t.Fatalf("Server.Addr = %q, want %q", cfg.Server.Addr, ":9999")
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
	if got := cfg.Storage.Serial.FilePath; got != "/tmp/serial.db" {
		t.Fatalf("Storage.Serial.FilePath = %q, want %q", got, "/tmp/serial.db")
	}
	if l := len(cfg.Authorize.PrincipalTemplates); l != 2 || cfg.Authorize.PrincipalTemplates[0] != "a" || cfg.Authorize.PrincipalTemplates[1] != "b" {
		t.Fatalf("Authorize.PrincipalTemplates = %+v, want [a b]", cfg.Authorize.PrincipalTemplates)
	}
}

func TestLoad_EnvOverridesAndParsing(t *testing.T) {
	t.Setenv("KAMINI_SERVER_ADDR", ":9090")
	t.Setenv("KAMINI_SERVER_REQUEST_TIMEOUT", "22s")               // duration
	t.Setenv("KAMINI_AUTHORIZE_ALLOW_ROLES", "admin, ops, dev")    // list
	t.Setenv("KAMINI_AUTH_OIDC_HTTP_TIMEOUT", "7s")                // nested duration via prefix mapping
	t.Setenv("KAMINI_SIGNER_CA_KEY_PATH", "/tmp/dev_ca")           // nested prefix mapping
	t.Setenv("KAMINI_STORAGE_SERIAL_FILE_PATH", "/tmp/serial2.db") // nested prefix mapping
	t.Setenv("KAMINI_LOG_LEVEL", "warn")                           // fallback mapping (single section)
	t.Setenv("KAMINI_LOG_FORMAT", "json,extra")                    // not a list key; should remain string

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Server.Addr != ":9090" {
		t.Fatalf("Server.Addr = %q, want %q", cfg.Server.Addr, ":9090")
	}
	if cfg.Server.RequestTimeout != 22*time.Second {
		t.Fatalf("Server.RequestTimeout = %v, want %v", cfg.Server.RequestTimeout, 22*time.Second)
	}
	if cfg.Auth.OIDC.HTTPTimeout != 7*time.Second {
		t.Fatalf("Auth.OIDC.HTTPTimeout = %v, want %v", cfg.Auth.OIDC.HTTPTimeout, 7*time.Second)
	}
	if l := len(cfg.Authorize.AllowRoles); l != 3 || cfg.Authorize.AllowRoles[0] != "admin" || cfg.Authorize.AllowRoles[1] != "ops" || cfg.Authorize.AllowRoles[2] != "dev" {
		t.Fatalf("Authorize.AllowRoles = %+v, want [admin ops dev]", cfg.Authorize.AllowRoles)
	}
	if cfg.Signer.CAKey.Path != "/tmp/dev_ca" {
		t.Fatalf("Signer.CAKey.Path = %q, want %q", cfg.Signer.CAKey.Path, "/tmp/dev_ca")
	}
	if cfg.Storage.Serial.FilePath != "/tmp/serial2.db" {
		t.Fatalf("Storage.Serial.FilePath = %q, want %q", cfg.Storage.Serial.FilePath, "/tmp/serial2.db")
	}
	if cfg.Log.Level != "warn" {
		t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "warn")
	}
	if cfg.Log.Format != "json,extra" {
		t.Fatalf("Log.Format = %q, want %q (no list split)", cfg.Log.Format, "json,extra")
	}
}

func TestLoad_EnvBoolParsing(t *testing.T) {
	t.Setenv("KAMINI_AUTH_OIDC_SKIP_CLIENT_ID_CHECK", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !cfg.Auth.OIDC.SkipClientIDCheck {
		t.Fatalf("SkipClientIDCheck = %v, want true", cfg.Auth.OIDC.SkipClientIDCheck)
	}
}

func TestLoad_EnvUnmarshalError_Bool(t *testing.T) {
	t.Setenv("KAMINI_AUTH_OIDC_SKIP_CLIENT_ID_CHECK", "nope")
	if _, err := Load(""); err == nil {
		t.Fatalf("Load expected error for bad bool, got nil")
	}
}

func TestLoad_EnvUnmarshalError_BadDuration(t *testing.T) {
	t.Setenv("KAMINI_SERVER_REQUEST_TIMEOUT", "banana")
	if _, err := Load(""); err == nil {
		t.Fatalf("expected error for bad duration, got nil")
	}
}

func TestEnvPrefixMapping_Claims(t *testing.T) {
	t.Setenv("KAMINI_AUTH_OIDC_CLAIMS_USERNAME", "sub")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Auth.OIDC.Claims.Username != "sub" {
		t.Fatalf("Claims.Username = %q, want %q", cfg.Auth.OIDC.Claims.Username, "sub")
	}
}

func TestLoad_DefaultsError(t *testing.T) {
	orig := defaultLoader
	t.Cleanup(func() { defaultLoader = orig })
	defaultLoader = func(k *koanf.Koanf) error { return fmt.Errorf("boom") }
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "load defaults") {
		t.Fatalf("expected load defaults error, got %v", err)
	}
}

func TestLoad_FileError(t *testing.T) {
	orig := fileLoader
	t.Cleanup(func() { fileLoader = orig })
	fileLoader = func(k *koanf.Koanf, path string) error { return fmt.Errorf("boom") }
	if _, err := Load("/does/not/matter.yaml"); err == nil || !strings.Contains(err.Error(), "load file") {
		t.Fatalf("expected load file error, got %v", err)
	}
}

func TestLoad_EnvError(t *testing.T) {
	orig := envLoader
	t.Cleanup(func() { envLoader = orig })
	envLoader = func(k *koanf.Koanf) error { return fmt.Errorf("boom") }
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "load env") {
		t.Fatalf("expected load env error, got %v", err)
	}
}
