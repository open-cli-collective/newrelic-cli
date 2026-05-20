// Init-gate ordering tests for the MON-5373 relocation gate. These pin the
// invariant that DetectConfigRelocation / ApplyConfigRelocation runs BEFORE
// keychain.OpenForInit (which would otherwise scrub the legacy plaintext
// credentials file as part of the §1.8 migration). MON-5372's lesson:
// asserting "no Save() happened" is not enough — seed a legacy artifact and
// assert it's still present post-abort to prove the gate ran before the
// migration could touch it.
package initcmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/initcmd"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

// TestRunInit_RelocationGate_OldOnlyCopied: the old hand-rolled location has
// a config.yml and the canonical doesn't — init copies old → new BEFORE
// running migration. Skipped on Linux (old==new).
func TestRunInit_RelocationGate_OldOnlyCopied(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux: old==new (statedir ≡ $XDG_CONFIG_HOME); gate is a no-op")
	}
	testutil.Setup(t)

	// Seed old hand-rolled config.yml.
	oldDir := filepath.Dir(testutil.LegacyCredentialsPath(t)) // …/.config/newrelic-cli
	require.NoError(t, os.WriteFile(filepath.Join(oldDir, "config.yml"),
		[]byte("credential_ref: newrelic-cli/default\naccount_id: \"42\"\nregion: EU\n"), 0o600))

	// Run init with --no-verify and a fresh api-key via stdin so it doesn't
	// fail loud — the gate should fire before keychain.OpenForInit either way.
	_, _, err := runInitStdin(t, "NRAK-test-relocate-001\n",
		"--api-key-stdin", "--no-verify", "--non-interactive")
	require.NoError(t, err)

	// Canonical config.yml now exists with copied content.
	cfgPath, err := config.Path()
	require.NoError(t, err)
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `account_id: "42"`)
	assert.Contains(t, string(raw), "region: EU")

	// Old config.yml still present (leave-old invariant).
	_, statErr := os.Stat(filepath.Join(oldDir, "config.yml"))
	assert.NoError(t, statErr, "old config.yml must remain (leave-old recovery point)")
}

// TestRunInit_RelocationGate_DivergentAbortsBeforeMutation: both paths hold
// materially-different configs AND a legacy credentials file is present at
// the OLD path. Init must abort BEFORE keychain.OpenForInit could run the
// §1.8 migration and scrub the legacy file. Asserting the legacy file is
// still present post-abort PROVES the gate runs ahead of migration (the
// MON-5372 ordering lesson).
func TestRunInit_RelocationGate_DivergentAbortsBeforeMutation(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux: old==new; gate is a no-op")
	}
	testutil.Setup(t)

	// Seed divergent configs at both paths.
	oldDir := filepath.Dir(testutil.LegacyCredentialsPath(t))
	require.NoError(t, os.WriteFile(filepath.Join(oldDir, "config.yml"),
		[]byte("credential_ref: newrelic-cli/old\n"), 0o600))

	canonical := testutil.ConfigDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(canonical, "config.yml"),
		[]byte("credential_ref: newrelic-cli/canonical\n"), 0o600))

	// Seed a plaintext legacy credentials file at the OLD path. If the gate
	// were to run AFTER keychain.OpenForInit, the §1.8 migration would
	// discover this and scrub it. Asserting it's still here post-abort is
	// the proof.
	legacyFile := testutil.LegacyCredentialsPath(t)
	require.NoError(t, os.WriteFile(legacyFile,
		[]byte("api_key=NRAK-init-ordering-proof\n"), 0o600))

	_, _, err := runInitStdin(t, "NRAK-test-divergent-002\n",
		"--api-key-stdin", "--no-verify", "--non-interactive")
	require.Error(t, err, "init must abort on a relocation conflict")

	// Two-part proof the GATE (not keychain.OpenForInit) rejected:
	//   (1) error message identifies the gate wrapper from runInit (Codex
	//       PR-r1 catch: a strict-Load failure inside OpenForInit would
	//       carry a different message — keychain.OpenForInit doesn't wrap
	//       with "detecting config relocation").
	//   (2) the legacy credentials file is UNTOUCHED — if the gate had run
	//       AFTER OpenForInit, the §1.8 migration would have scrubbed it
	//       (and the absent file would be visible here).
	assert.Contains(t, err.Error(), "detecting config relocation",
		"error must come from runInit's gate wrapper, not a downstream strict-Load failure")
	_, statErr := os.Stat(legacyFile)
	assert.NoError(t, statErr,
		"legacy credentials file must still exist — proves the gate ran before §1.8 migration scrub")
}

// runInitStdin is runInit with a piped stdin string for --api-key-stdin.
func runInitStdin(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	rootCmd, opts := root.NewRootCmd()
	var out, errb bytes.Buffer
	opts.Stdout, opts.Stderr = &out, &errb
	opts.Stdin = bytes.NewBufferString(stdin)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	root.RegisterAll(rootCmd, opts, func(c *cobra.Command, o *root.Options) {
		initcmd.Register(c, o)
	})
	rootCmd.SetArgs(append([]string{"init"}, args...))
	err := rootCmd.Execute()
	return out.String(), errb.String(), err
}
