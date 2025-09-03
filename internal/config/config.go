package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
)

// Root is the application configuration.
type Root struct {
	Server    ServerConfig    `koanf:"server"`
	Log       LogConfig       `koanf:"log"`
	Auth      AuthConfig      `koanf:"auth"`
	Authorize AuthorizeConfig `koanf:"authorize"`
	Signer    SignerConfig    `koanf:"signer"`
	Storage   StorageConfig   `koanf:"storage"`
	Audit     AuditConfig     `koanf:"audit"`
}

type ServerConfig struct {
	Addr           string        `koanf:"addr"`
	RequestTimeout time.Duration `koanf:"request_timeout"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

type AuthConfig struct {
	OIDC OIDCConfig `koanf:"oidc"`
}

type OIDCConfig struct {
	IssuerURL         string        `koanf:"issuer_url"`
	ClientID          string        `koanf:"client_id"`
	SkipClientIDCheck bool          `koanf:"skip_client_id_check"`
	Claims            OIDCClaims    `koanf:"claims"`
	HTTPTimeout       time.Duration `koanf:"http_timeout"`
}

type OIDCClaims struct {
	Username string `koanf:"username"`
	Email    string `koanf:"email"`
	Roles    string `koanf:"roles"`
	Groups   string `koanf:"groups"`
}

type AuthorizeConfig struct {
	AllowRoles         []string      `koanf:"allow_roles"`
	AllowGroups        []string      `koanf:"allow_groups"`
	PrincipalTemplates []string      `koanf:"principal_templates"`
	DefaultTTL         time.Duration `koanf:"default_ttl"`
	MaxTTL             time.Duration `koanf:"max_ttl"`
	SourceCIDRs        []string      `koanf:"source_cidrs"`
}

type SignerConfig struct {
	CAKey CAKeyConfig `koanf:"ca_key"`
}

type CAKeyConfig struct {
	Path string `koanf:"path"`
}

type StorageConfig struct {
	Serial SerialConfig `koanf:"serial"`
}

type SerialConfig struct {
	FilePath string `koanf:"file_path"`
}

type AuditConfig struct {
	Sink string `koanf:"sink"`
}

// Defaults returns an opinionated default configuration.
var DEFAULT_CONFIG = Root{
	Server: ServerConfig{
		Addr:           ":8080",
		RequestTimeout: 15 * time.Second,
	},
	Log: LogConfig{Level: "info", Format: "json"},
	Auth: AuthConfig{OIDC: OIDCConfig{
		Claims:      OIDCClaims{Username: "preferred_username", Email: "email", Roles: "roles", Groups: "groups"},
		HTTPTimeout: 10 * time.Second,
	}},
	Authorize: AuthorizeConfig{
		DefaultTTL: 1 * time.Hour,
		MaxTTL:     8 * time.Hour,
	},
	Audit: AuditConfig{Sink: "stdout"},
}

// Load loads configuration from defaults, then optional YAML file, then env overrides.
// If path is empty, the YAML step is skipped. Env prefix is KAMINI_.
func Load(path string) (Root, error) {
	k := koanf.New(".")

	// seed defaults
	err := defaultLoader(k)
	if err != nil {
		return Root{}, fmt.Errorf("load defaults: %w", err)
	}

	// file is optional
	err = fileLoader(k, path)
	if err != nil {
		return Root{}, fmt.Errorf("load file: %w", err)
	}

	// env overrides
	// Example: KAMINI_SERVER_ADDR=":8081" -> server.addr
	err = envLoader(k)
	if err != nil {
		return Root{}, fmt.Errorf("load env: %w", err)
	}

	// declare the config variable
	var cfg Root

	// unmarshal merged into cfg using Koanf defaults (built-in type decoding)
	if err := k.Unmarshal("", &cfg); err != nil {
		return Root{}, fmt.Errorf("unmarshal: %w", err)
	}

	return cfg, nil
}

// defaultLoader loads the default configuration into the provided Koanf instance.
// It uses the structs.Provider to load configuration from the DEFAULT_CONFIG variable
// with the "koanf" tag. Returns an error if loading fails.
var defaultLoader = func(k *koanf.Koanf) error {
	return k.Load(structs.Provider(DEFAULT_CONFIG, "koanf"), nil)
}

// fileLoader loads configuration from the specified file path into the provided Koanf instance.
// If the path is empty, it does nothing and returns nil.
// Otherwise, it loads the file using the file provider and parses it as YAML.
// Returns an error if loading or parsing fails.
var fileLoader = func(k *koanf.Koanf, path string) error {
	if path == "" {
		return nil
	}
	return k.Load(file.Provider(path), yaml.Parser())
}

// envLoader loads environment variables into a Koanf instance, transforming keys and values.
// Keys with the "KAMINI_" prefix are converted to lowercase, the prefix is removed, and underscores are replaced with dots.
// Values containing commas are split into string slices, allowing for list-type configuration via environment variables.
// For example, KAMINI_AUTHORIZE_ALLOW_ROLES="admin,ops" becomes ["admin", "ops"].
// Returns an error if loading fails.
var envLoader = func(k *koanf.Koanf) error {
	// Keys that should be treated as lists when values contain commas
	listKeys := map[string]struct{}{
		"authorize.allow_roles":         {},
		"authorize.allow_groups":        {},
		"authorize.principal_templates": {},
		"authorize.source_cidrs":        {},
	}

	// Keys whose values are durations (parsed via time.ParseDuration when sourced from env)
	durationKeys := map[string]struct{}{
		"server.request_timeout": {},
		"auth.oidc.http_timeout": {},
		"authorize.default_ttl":  {},
		"authorize.max_ttl":      {},
	}

	return k.Load(env.Provider(".", env.Opt{
		Prefix: "KAMINI_",
		TransformFunc: func(k, v string) (string, any) {
			// Normalize
			raw := strings.ToLower(strings.TrimPrefix(k, "KAMINI_"))

			// Explicit nested-prefix mapping to avoid clobbering underscores in field names
			switch {
			case strings.HasPrefix(raw, "auth_oidc_claims_"):
				k = "auth.oidc.claims." + strings.TrimPrefix(raw, "auth_oidc_claims_")
			case strings.HasPrefix(raw, "auth_oidc_"):
				k = "auth.oidc." + strings.TrimPrefix(raw, "auth_oidc_")
			case strings.HasPrefix(raw, "signer_ca_key_"):
				k = "signer.ca_key." + strings.TrimPrefix(raw, "signer_ca_key_")
			case strings.HasPrefix(raw, "storage_serial_"):
				k = "storage.serial." + strings.TrimPrefix(raw, "storage_serial_")
			default:
				// Fallback: only the first underscore delimits top-level.section
				if i := strings.IndexByte(raw, '_'); i >= 0 {
					k = raw[:i] + "." + raw[i+1:]
				} else {
					k = raw
				}
			}

			// Durations: parse only for known duration keys
			if _, ok := durationKeys[k]; ok {
				if d, err := time.ParseDuration(v); err == nil {
					return k, d
				}
				// fall through to raw string if parsing fails
			}

			// Only split lists for known list keys
			if strings.Contains(v, ",") {
				if _, ok := listKeys[k]; ok {
					parts := strings.Split(v, ",")
					out := make([]string, 0, len(parts))
					for _, p := range parts {
						s := strings.TrimSpace(p)
						if s != "" {
							out = append(out, s)
						}
					}
					return k, out
				}
			}
			return k, v
		},
	}), nil)
}
