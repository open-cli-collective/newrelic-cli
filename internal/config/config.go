// Package config holds nrq's non-secret on-disk configuration per the Open
// CLI Collective Secret-Handling Standard §1.2 / §2.5. No access secret is
// ever written here — the New Relic API key lives only in the OS keyring via
// cli-common's credstore (see internal/keychain). This file owns config.yml:
// the authoritative credential_ref (§1.3), the non-secret account_id/region,
// and the optional §1.4 file-backend opt-in.
//
// §2.5 decisions encoded here:
//   - account_id / region are non-secret runtime config, NOT credentials.
//   - NEWRELIC_ACCOUNT_ID / NEWRELIC_REGION remain non-secret runtime
//     overrides with precedence env > config.yml (they are not secret /
//     unlocking material, so they do not fall under §1.11's env ban).
//   - There is NO api_key accessor in this package. The only runtime path to
//     the secret is the keychain adapter, reached via the command layer's
//     lazy API-client resolver.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultCredentialRef applies when config.yml is absent or omits
	// credential_ref. It is still parsed through credstore.ParseRef by
	// callers — never assumed structurally (§1.3 / §2.5).
	DefaultCredentialRef = "newrelic-cli/default"

	// DefaultRegion is New Relic's US data center, used when neither the
	// env override nor config.yml specifies a region (preserves the legacy
	// "US" default).
	DefaultRegion = "US"

	appDirName     = "newrelic-cli"
	configFileName = "config.yml"

	envAccountID = "NEWRELIC_ACCOUNT_ID"
	envRegion    = "NEWRELIC_REGION"
)

// Source describes where a resolved non-secret value came from, for
// `config show` (§2.5: show the source of each non-secret value).
type Source string

const (
	SourceEnv    Source = "env"
	SourceConfig Source = "config"
	SourceUnset  Source = "unset"
)

// Config is nrq's config.yml. Everything here is safe for an org to commit to
// a private/MDM-controlled store (§1.2); none of it is an access secret.
type Config struct {
	// CredentialRef is the authoritative <service>/<profile> keyring ref
	// (§1.3). Callers resolve it via credstore.ParseRef; the service and
	// profile are never hard-coded from a convention.
	CredentialRef string `yaml:"credential_ref"`
	// AccountID is the non-secret New Relic account ID.
	AccountID string `yaml:"account_id,omitempty"`
	// Region is the non-secret New Relic data center ("US" or "EU").
	Region string `yaml:"region,omitempty"`
	// Keyring carries the optional §1.4 explicit file-backend opt-in.
	Keyring KeyringConfig `yaml:"keyring,omitempty"`
}

// KeyringConfig is the §1.4 backend selector. Backend == "file" forces the
// encrypted-file backend unconditionally; empty means OS default selection.
type KeyringConfig struct {
	Backend string `yaml:"backend,omitempty"`
}

// Dir is the cross-platform config directory: $XDG_CONFIG_HOME/newrelic-cli
// else ~/.config/newrelic-cli. Identical on Linux, macOS, and Windows — this
// matches the released legacy layout (the legacy code has no %APPDATA%
// branch), so config.yml sits beside the legacy credentials file it
// supersedes and migration discovery needs no platform special-casing.
func Dir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, appDirName)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", appDirName)
}

// Path is the config.yml location.
func Path() string { return filepath.Join(Dir(), configFileName) }

// Load reads config.yml. An absent file is not an error: defaults are applied
// (CredentialRef = DefaultCredentialRef) and a usable Config is returned.
func Load() (*Config, error) {
	c := &Config{}
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			c.applyDefaults()
			return c, nil
		}
		return nil, fmt.Errorf("read config %s: %w", Path(), err)
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", Path(), err)
	}
	c.applyDefaults()
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.CredentialRef == "" {
		c.CredentialRef = DefaultCredentialRef
	}
}

// Save writes config.yml at 0600 under a 0700 directory, ATOMICALLY
// (write to a temp file in the same dir, then rename). A crash mid-write
// must not leave a truncated config.yml: it carries credential_ref (§1.3),
// and a partial file would silently fall back to DefaultCredentialRef on
// the next Open() — pointing at a different keyring bundle than the user
// configured. Non-secret, but no reason to be world-readable.
func (c *Config) Save() error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp, err := os.CreateTemp(Dir(), ".config-*.yml.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, Path()); err != nil {
		return fmt.Errorf("rename config into place %s: %w", Path(), err)
	}
	return nil
}

// LegacyCredentialsPath is the pre-credstore plaintext file location. It is
// derived from Dir() so it provably tracks the SAME XDG/HOME resolution as
// config.yml — the old code respected XDG_CONFIG_HOME, and the §1.8
// migration must look exactly where the old code wrote.
func LegacyCredentialsPath() string { return filepath.Join(Dir(), "credentials") }

// ResolveAccountID returns the effective account ID and its source.
// Precedence is env > config.yml (§2.5: non-secret runtime override useful
// for multi-account scripting). Empty config + no env → ("", SourceUnset).
func (c *Config) ResolveAccountID() (string, Source) {
	if v := strings.TrimSpace(os.Getenv(envAccountID)); v != "" {
		return v, SourceEnv
	}
	if c.AccountID != "" {
		return c.AccountID, SourceConfig
	}
	return "", SourceUnset
}

// ResolveRegion returns the effective region (upper-cased) and its source.
// Precedence is env > config.yml > built-in "US" default. The default is
// reported as SourceUnset (neither env nor config supplied it).
func (c *Config) ResolveRegion() (string, Source) {
	if v := strings.TrimSpace(os.Getenv(envRegion)); v != "" {
		return strings.ToUpper(v), SourceEnv
	}
	if c.Region != "" {
		return strings.ToUpper(c.Region), SourceConfig
	}
	return DefaultRegion, SourceUnset
}
