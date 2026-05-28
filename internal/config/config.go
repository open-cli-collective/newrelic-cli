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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-cli-collective/cli-common/statedir"
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
	credFileName   = "credentials"

	// DirPerm/FilePerm are the family-wide on-disk perms (§1.2): 0700 for
	// the config dir, 0600 for config.yml and any temp file in flight.
	DirPerm  = 0o700
	FilePerm = 0o600

	envAccountID = "NEWRELIC_ACCOUNT_ID"
	envRegion    = "NEWRELIC_REGION"
)

// configScope is the family-wide shared resolver for nrq's config dir.
// Single-binary CLI ⇒ scope name = tool/repo name (working-with-state.md §6.4).
var configScope = statedir.Scope{Name: appDirName}

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

// Dir is the cross-platform config directory, resolved by cli-common's
// statedir.Scope: native per OS (Linux `$XDG_CONFIG_HOME`/`~/.config`, macOS
// `~/Library/Application Support`, Windows `%APPDATA%`). A relative
// `$XDG_CONFIG_HOME` is a hard error (§1.1: no cwd fallback).
func Dir() (string, error) { return configScope.ConfigDir() }

// Path is the config.yml location.
func Path() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, configFileName), nil
}

// CanonicalCredentialsPath is the post-port location of nrq's plaintext
// credentials file (Dir() + "credentials"). After the resolver switch this
// is where a hand-rolled write WOULD land on macOS/Windows — symmetric with
// the pre-port location on Linux.
func CanonicalCredentialsPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, credFileName), nil
}

// CredentialFileCandidates returns the plaintext credentials-file paths the
// §1.8 migrator scans AND `clear --all` scrubs: [OldHandRolledCredentialsPath,
// CanonicalCredentialsPath], path-identity deduped (Linux old≡new collapses
// to one). The single shared helper means migrator and clear can never drift.
func CredentialFileCandidates() ([]string, error) {
	canonical, err := CanonicalCredentialsPath()
	if err != nil {
		return nil, err
	}
	old, oerr := OldHandRolledCredentialsPath()
	if oerr == nil && old != canonical {
		return []string{old, canonical}, nil
	}
	return []string{canonical}, nil
}

// Load reads config.yml. An absent file is not an error: defaults are applied
// (CredentialRef = DefaultCredentialRef) and a usable Config is returned.
// Relocation-aware: on a macOS/Windows resolver-switch transition where only
// the old hand-rolled path holds a config.yml, Load reads that as a fallback
// (mutation-free — init owns the actual copy). On a both-present divergence
// it returns the canonical config AND a non-nil ErrRelocationConflict-wrapped
// error so non-init callers can choose to hard-fail (strict Load) vs
// soft-degrade (LoadForRuntime).
func Load() (*Config, error) {
	newDir, err := Dir()
	if err != nil {
		return nil, err
	}
	return loadFromNewDir(newDir)
}

// HasUserConfig reports whether a config.yml exists at the canonical path
// or a relocation-fallback path. Mirrors loadFromNewDir's file-presence
// semantics (including relocOldOnly). Callers should treat malformed
// configs as errors, not silently as "no config" — set-credential uses
// this to decide whether --ref is required per §1.5.2 (--ref defaults to
// the active config's credential_ref only if a config file already exists).
func HasUserConfig() (bool, error) {
	newDir, err := Dir()
	if err != nil {
		return false, err
	}
	return hasUserConfigInDir(newDir)
}

// hasUserConfigInDir is the testable seam — production AND tests both call
// this. Splitting the dir resolution from the file probe lets the relocation
// suite exercise old-only / malformed paths without re-implementing them
// (mirrors the loadFromNewDir / Load split in this file).
func hasUserConfigInDir(newDir string) (bool, error) {
	newYML := filepath.Join(newDir, configFileName)
	if _, found, err := readConfigYML(newYML); err != nil {
		return false, err
	} else if found {
		return true, nil
	}

	reloc, relErr := detectRelocation(newDir)
	if relErr != nil {
		// Propagate any error — ErrRelocationConflict, malformed-old,
		// permission errors, etc. Silently swallowing non-conflict errors
		// would misreport "no config exists" on a box where config does
		// exist but is temporarily unreadable, causing set-credential to
		// incorrectly demand --ref.
		return false, relErr
	}
	if reloc.Kind == relocOldOnly {
		oldYML := filepath.Join(reloc.OldPath, configFileName)
		if _, found, err := readConfigYML(oldYML); err != nil {
			return false, err
		} else if found {
			return true, nil
		}
	}
	return false, nil
}

// loadFromNewDir is the testable seam — production AND tests both call this.
// Splitting it out avoids the "test helper as parallel implementation" trap
// (slck MON-5372 Codex r1 lesson): production can never silently regress
// past a passing test.
func loadFromNewDir(newDir string) (*Config, error) {
	newYML := filepath.Join(newDir, configFileName)
	reloc, relErr := detectRelocation(newDir)

	// Try canonical first (the post-port location).
	c, read, err := readConfigYML(newYML)
	if err != nil {
		// Canonical exists but is unreadable/malformed — propagate.
		// Under a relocation conflict, the canonical-malformed signal must
		// surface as ErrRelocationConflict so LoadForRuntime cannot
		// soft-degrade and silently swap CredentialRef to default (the
		// MON-5371 contract).
		if relErr != nil && errors.Is(relErr, ErrRelocationConflict) {
			return nil, relErr
		}
		return nil, err
	}
	if read {
		// Canonical readable. Apply defaults; if also under conflict, return
		// the cfg + the wrapped conflict error so LoadForRuntime can warn-
		// and-soft-degrade with a real cfg (cfg != nil contract).
		c.applyDefaults()
		out := c
		if relErr != nil {
			return &out, relErr
		}
		return &out, nil
	}

	// Canonical absent. Try the old hand-rolled location as a runtime
	// fallback (Linux: same path, already covered). Mutation-free — init's
	// gate owns the actual copy.
	if reloc.Kind == relocOldOnly {
		oldYML := filepath.Join(reloc.OldPath, configFileName)
		oc, oread, oerr := readConfigYML(oldYML)
		if oerr != nil {
			return nil, oerr
		}
		if oread {
			oc.applyDefaults()
			return &oc, nil
		}
	}

	// Neither — absent on both sides; defaults.
	if relErr != nil && errors.Is(relErr, ErrRelocationConflict) {
		// Conflict without a readable canonical: the only way this happens
		// is a malformed pair detected by detectRelocation; hard-fail.
		return nil, relErr
	}
	out := &Config{}
	out.applyDefaults()
	return out, nil
}

// readConfigYML parses one path; returns (cfg, found, err). Missing file
// returns (zero, false, nil) — distinct from a malformed parse.
func readConfigYML(path string) (Config, bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path composed from validated config dir
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, false, nil
		}
		return Config{}, false, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if uerr := yaml.Unmarshal(data, &c); uerr != nil {
		return Config{}, false, fmt.Errorf("parse config %s: %w", path, uerr)
	}
	return c, true, nil
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
	dir, err := configScope.ConfigDirEnsured()
	if err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	path := filepath.Join(dir, configFileName)
	data, merr := yaml.Marshal(c)
	if merr != nil {
		return fmt.Errorf("marshal config: %w", merr)
	}
	tmp, terr := os.CreateTemp(dir, ".config-*.yml.tmp")
	if terr != nil {
		return fmt.Errorf("create temp config: %w", terr)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if err := tmp.Chmod(FilePerm); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename config into place %s: %w", path, err)
	}
	return nil
}

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
