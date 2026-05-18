// Package keychain is nrq's credential adapter. Despite the historical
// package name it no longer shells out to macOS `security` or writes a
// plaintext file: it is a thin wrapper over cli-common's credstore, which
// owns OS-keyring storage, §1.4 backend selection (incl. Linux fail-closed
// and the encrypted-file fallback, and Windows Credential Manager), and the
// §1.5.2 allowed-key allowlist. The name is retained to avoid churning every
// importer (Open CLI Collective Secret-Handling Standard §2.5).
//
// All runtime credential resolution goes through here and reads the OS
// keyring only — never an environment variable, never a config field
// (§1.11 acceptance item 2). NEWRELIC_API_KEY carries secret material into
// nrq solely as *ingress* during `init` / `set-credential`.
package keychain

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
)

// KeyAPIKey is nrq's sole bundle key (§2.5: keys under newrelic-cli/<profile>
// = {api_key}). New Relic has one logical access credential, so §1.3's
// one-key-per-logical-credential default applies and no exception is claimed.
const KeyAPIKey = "api_key"

// allowedKeys is nrq's §1.5.2 allowlist: exactly the one bundle key.
var allowedKeys = []string{KeyAPIKey}

// Store is an open handle to nrq's credential bundle. Construct with Open,
// always Close. It carries the resolved ref so callers can report it in
// `config show` / errors without re-deriving it (§1.12: ref is not secret).
type Store struct {
	cs      *credstore.Store
	service string
	profile string
	ref     string
}

// Open resolves the authoritative credential_ref from config.yml (§1.3 —
// the service/profile are parsed, never assumed), opens the backing
// credstore, and runs the one-time legacy migration (§1.8) before returning.
// The returned Store reads/writes the OS keyring only. A legacy-vs-keyring
// conflict surfaces here as a §1.8 error; `nrq init --overwrite` calls
// OpenForMigrationOverwrite to force the legacy value instead.
func Open() (*Store, error) { return open(false, true) }

// OpenForMigrationOverwrite is Open with the §1.8 `--overwrite` resolution:
// a legacy value is forced over an existing keyring entry. It still cannot
// resolve a legacy-vs-legacy disagreement (the user must pick).
func OpenForMigrationOverwrite() (*Store, error) { return open(true, true) }

// OpenNoMigrate opens the store WITHOUT running the one-time migration. It
// exists so `config clear` can perform the §1.8 conflict remediation it
// advertises: if migration ran first it would return the conflict error
// before clear could delete the keyring entry, leaving the user no way out.
func OpenNoMigrate() (*Store, error) { return open(false, false) }

func open(overwrite, runMigration bool) (*Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return openWith(cfg, overwrite, runMigration)
}

// OpenRef opens a store against an explicit ref instead of config.yml's
// credential_ref — used by `nrq set-credential --ref` (§1.5.2 ingress). An
// empty ref falls back to the configured/default ref. Migration does NOT run
// here: the one-time §1.8 migration only ever targets the canonical
// configured ref. set-credential is pure ingress; migration still runs on the
// next init / first API call via the default Open path.
func OpenRef(ref string) (*Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if ref != "" {
		cfg.CredentialRef = ref
	}
	return openWith(cfg, false, false)
}

// openWith is the seam unit tests drive with an injected config (e.g. a
// file-backend opt-in via Keyring.Backend) so they never touch a real
// keyring (§1.12 test obligation, and hermeticity).
func openWith(cfg *config.Config, overwrite, runMigration bool) (*Store, error) {
	service, profile, err := credstore.ParseRef(cfg.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("invalid credential_ref %q: %w", cfg.CredentialRef, err)
	}

	opts := &credstore.Options{AllowedKeys: allowedKeys}
	switch b := strings.TrimSpace(cfg.Keyring.Backend); b {
	case "":
		// Auto-select per §1.4 (credstore decides; fail-closed on Linux).
	case "file":
		opts.ConfigBackend = credstore.BackendFile
	default:
		// Fail closed: an unrecognized backend must not silently degrade to
		// auto-selection and store credentials somewhere unintended.
		return nil, fmt.Errorf("invalid keyring.backend %q in config (only \"file\" is supported)", b)
	}
	opts.FilePassphrase = passphraseFunc(service)

	cs, err := credstore.Open(service, opts)
	if err != nil {
		return nil, err
	}

	s := &Store{cs: cs, service: service, profile: profile, ref: cfg.CredentialRef}

	if runMigration {
		if err := migrateLegacyOverwrite(s, cfg, overwrite); err != nil {
			_ = cs.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close releases the backing store. Safe on a nil receiver.
func (s *Store) Close() error {
	if s == nil || s.cs == nil {
		return nil
	}
	return s.cs.Close()
}

// Ref returns the resolved credential ref (non-secret; safe to display).
func (s *Store) Ref() string { return s.ref }

// Service returns the resolved service segment (non-secret; used for the
// §1.4 passphrase-source display).
func (s *Store) Service() string { return s.service }

// Backend reports the credstore backend and how it was selected, for
// `config show` (§2.5). Neither value is secret.
func (s *Store) Backend() (credstore.Backend, credstore.Source) { return s.cs.Backend() }

// APIKey returns the New Relic API key from the keyring. ErrMissingAPIKey
// (an errors.Is-matchable wrapper of credstore.ErrNotFound) when unset.
func (s *Store) APIKey() (string, error) {
	v, err := s.cs.Get(s.profile, KeyAPIKey)
	if errors.Is(err, credstore.ErrNotFound) || (err == nil && v == "") {
		return "", ErrMissingAPIKey
	}
	if err != nil {
		// Never embed the value; naming ref/key/op is allowed (§1.12).
		return "", fmt.Errorf("read %s from %s: %w", KeyAPIKey, s.ref, err)
	}
	return v, nil
}

// SetAPIKey is the default ingress write: it FAILS (credstore.ErrExists) if
// an api_key already exists under the ref. §1.5/§1.11 posture — an existing
// keyring entry is never silently clobbered; the caller must obtain explicit
// user intent (`--overwrite`) and use SetAPIKeyOverwrite.
func (s *Store) SetAPIKey(v string) error { return s.set(v, false) }

// SetAPIKeyOverwrite replaces an existing api_key. Only reached after the
// command layer has an explicit `--overwrite`.
func (s *Store) SetAPIKeyOverwrite(v string) error { return s.set(v, true) }

func (s *Store) set(v string, overwrite bool) error {
	var opts []credstore.SetOpt
	if overwrite {
		opts = append(opts, credstore.WithOverwrite())
	}
	if err := s.cs.Set(s.profile, KeyAPIKey, v, opts...); err != nil {
		// ErrExists is propagated verbatim (errors.Is-matchable) so the
		// command layer can turn it into the actionable --overwrite hint.
		if errors.Is(err, credstore.ErrExists) {
			return err
		}
		return fmt.Errorf("store %s at %s: %w", KeyAPIKey, s.ref, err)
	}
	return nil
}

// DeleteAPIKey removes the key (idempotent: a missing key is not an error —
// §1.7).
func (s *Store) DeleteAPIKey() error {
	if ok, _ := s.cs.Exists(s.profile, KeyAPIKey); !ok {
		return nil
	}
	if err := s.cs.Delete(s.profile, KeyAPIKey); err != nil && !errors.Is(err, credstore.ErrNotFound) {
		return fmt.Errorf("delete %s at %s: %w", KeyAPIKey, s.ref, err)
	}
	return nil
}

// HasAPIKey reports presence without returning the value (used by
// `config show` / `init` overwrite prompts — §2.5: presence only).
func (s *Store) HasAPIKey() bool {
	ok, err := s.cs.Exists(s.profile, KeyAPIKey)
	return err == nil && ok
}

// Clear removes the whole bundle under the active profile (config clear,
// §1.7). Idempotent; scope is the active profile only.
func (s *Store) Clear() ([]string, error) {
	return s.cs.DeleteBundle(s.profile)
}

// ErrMissingAPIKey is the sentinel for "no api_key in the keyring".
// errors.Is(err, ErrMissingAPIKey) lets the CLI print an actionable setup
// hint without leaking anything.
var ErrMissingAPIKey = errors.New(
	"nrq: no API key in keyring — run `nrq init` or " +
		"`nrq set-credential --key api_key --stdin`")
