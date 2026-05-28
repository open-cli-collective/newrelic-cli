// Package testutil provides a hermetic credential environment for tests
// (§1.12 test obligation / §2 deliverable 11). It delegates state-dir
// isolation to the shared cli-common/statedirtest helper (the full 7-var
// env set per §3.1 — closes the Windows real-dir leak the old HOME/XDG-only
// setup had), then layers nrq's keyring-backend selection on top.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-cli-collective/cli-common/statedirtest"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
)

// Setup isolates the full §3.1 7-var env set under t.TempDir() (via
// statedirtest.Hermetic) and forces credstore's file backend with a known
// passphrase. It also clears every NEWRELIC_* env var so a developer's real
// shell environment cannot leak into a test, and neutralizes the darwin
// legacy-Keychain probe so the suite is hermetic. Returns the temp root.
// Tests should resolve paths via ConfigDir(t) / LegacyCredentialsPath(t)
// below rather than hand-building subdirs, because os.UserConfigDir is
// platform-native (macOS ~/Library/Application Support, Windows %APPDATA%)
// and not derived from any single env var.
func Setup(t *testing.T) string {
	t.Helper()
	tmp := statedirtest.Hermetic(t)

	// Force credstore's encrypted-file backend (never the real Keychain /
	// Secret Service / Credential Manager), passphrase supplied non-
	// interactively.
	t.Setenv("NEWRELIC_CLI_KEYRING_BACKEND", "file")
	t.Setenv("NEWRELIC_CLI_KEYRING_PASSPHRASE", "test-passphrase")

	// Neutralize the darwin legacy-Keychain `security` probe so the suite
	// is hermetic; tests that exercise keychain migration set this back.
	t.Setenv("NRQ_TEST_DISABLE_LEGACY_KEYCHAIN_SCAN", "1")

	// A developer's real NEWRELIC_* must never bleed into a test's
	// resolution/ingress assertions.
	for _, e := range []string{"NEWRELIC_API_KEY", "NEWRELIC_ACCOUNT_ID", "NEWRELIC_REGION"} {
		t.Setenv(e, "")
		_ = os.Unsetenv(e)
	}

	return tmp
}

// ConfigDir resolves the post-statedirtest hermetic CANONICAL config dir
// (statedir-resolved per OS) and creates it. Tests that plant or inspect
// `config.yml` should use this rather than hand-building subdirs.
func ConfigDir(t *testing.T) string {
	t.Helper()
	dir, err := config.Dir()
	if err != nil {
		t.Fatalf("testutil.ConfigDir: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("testutil.ConfigDir mkdir: %v", err)
	}
	return dir
}

// LegacyCredentialsPath returns the pre-MON-5373 hand-rolled `credentials`
// file path: $XDG_CONFIG_HOME/newrelic-cli/credentials else
// $HOME/.config/newrelic-cli/credentials. Distinct from ConfigDir on
// macOS/Windows where the canonical resolver returns a different OS-native
// path. Tests that seed/inspect the legacy plaintext credentials file (the
// secret-bearing key=value fixture, NOT config.yml) must use this helper.
// Returns the absolute path; the parent dir is created so tests can
// os.WriteFile immediately.
func LegacyCredentialsPath(t *testing.T) string {
	t.Helper()
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, _ := os.UserHomeDir()
		configHome = filepath.Join(home, ".config")
	}
	dir := filepath.Join(configHome, "newrelic-cli")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("testutil.LegacyCredentialsPath mkdir: %v", err)
	}
	return filepath.Join(dir, "credentials")
}
