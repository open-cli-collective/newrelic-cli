// Package testutil provides a hermetic credential environment for tests
// (§1.12 test obligation / §2 deliverable 11). It forces credstore's
// encrypted-file backend inside a per-test temp HOME with a fixed
// passphrase, so no test ever touches the real OS keyring, shells out to
// `security`, or depends on machine state.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-cli-collective/newrelic-cli/internal/output"
)

// Setup isolates HOME/XDG to a temp dir and forces the file backend with a
// known passphrase via the §1.4 named env vars. It also clears every
// NEWRELIC_* env var so a developer's real shell environment cannot leak
// into a test, and neutralizes the darwin legacy-Keychain probe so the
// suite is hermetic. Returns the temp dir so a test can plant legacy
// artifacts (e.g. a legacy credentials file) under it.
func Setup(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "xdgconfig"))

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

	// A prior test's recorded §1.8 block must never bleed into this one's
	// JSON output.
	output.ResetMigration()
	t.Cleanup(output.ResetMigration)
	return tmp
}
