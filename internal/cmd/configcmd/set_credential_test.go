package configcmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

// secretSentinel is a recognizable string that must never appear in any
// captured stdout / stderr / envelope, per §1.12.
const secretSentinel = "NRAK-DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD"

// runSetCredentialViaRoot executes `nrq set-credential <args>` end-to-end
// through the root command so this exercises cobra flag parsing, the
// PersistentPreRunE chain (incl. SilenceErrors wiring), and stdout/stderr
// routing — not just the inner runSetCredential function.
func runSetCredentialViaRoot(t *testing.T, stdin string, args ...string) (stdout, stderr *bytes.Buffer, err error) {
	t.Helper()
	rootCmd, opts := root.NewRootCmd()
	stdout = &bytes.Buffer{}
	stderr = &bytes.Buffer{}
	opts.Stdout, opts.Stderr = stdout, stderr
	opts.Stdin = strings.NewReader(stdin)
	root.RegisterAll(rootCmd, opts, Register)
	rootCmd.SetArgs(append([]string{"set-credential"}, args...))
	err = rootCmd.Execute()
	return stdout, stderr, err
}

// parseEnvelope decodes the single JSON line emitted on stdout.
func parseEnvelope(t *testing.T, stdout *bytes.Buffer) setCredentialEnvelope {
	t.Helper()
	var env setCredentialEnvelope
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &env), "stdout is not a valid JSON envelope:\n%s", stdout.String())
	return env
}

// --- JSON envelope tests ----------------------------------------------------

func TestSetCredential_JSONSuccess(t *testing.T) {
	testutil.Setup(t)
	stdout, stderr, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin", "--json")
	require.NoError(t, err)

	env := parseEnvelope(t, stdout)
	assert.Equal(t, "newrelic-cli/test", env.Ref)
	assert.Equal(t, "api_key", env.Key)
	assert.NotEmpty(t, env.Backend, "post-keyring success must populate backend")
	assert.True(t, env.Written)
	assert.Empty(t, env.Error)

	// Stderr empty — no human Success() line when --json.
	assert.Empty(t, stderr.String(), "stderr must be empty on --json success")

	// §1.12: never leak the secret on any captured stream.
	assert.NotContains(t, stdout.String()+stderr.String(), secretSentinel)
}

func TestSetCredential_JSONFailure_ExistingKey_PostKeyring(t *testing.T) {
	testutil.Setup(t)
	// Seed an existing value.
	_, _, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin")
	require.NoError(t, err)

	// Re-run without --overwrite; expect post-keyring failure envelope.
	stdout, stderr, err := runSetCredentialViaRoot(t,
		"NRAK-other-value\n",
		"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin", "--json")
	require.Error(t, err, "exit must be non-zero on no-clobber failure")

	env := parseEnvelope(t, stdout)
	assert.Equal(t, "newrelic-cli/test", env.Ref)
	assert.Equal(t, "api_key", env.Key)
	assert.NotEmpty(t, env.Backend, "post-keyring failure must still populate backend")
	assert.False(t, env.Written)
	assert.Contains(t, env.Error, "--overwrite")

	// SilenceErrors must have prevented cobra from re-printing the error.
	assert.Empty(t, stderr.String(), "stderr must be empty on --json failure (SilenceErrors)")

	// §1.12: no secret leakage on the failure path either.
	combined := stdout.String() + stderr.String()
	assert.NotContains(t, combined, secretSentinel)
	assert.NotContains(t, combined, "NRAK-other-value")
}

func TestSetCredential_JSONFailure_InvalidKey_PreKeyring(t *testing.T) {
	testutil.Setup(t)
	stdout, stderr, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--ref", "newrelic-cli/test", "--key", "bogus_key", "--stdin", "--json")
	require.Error(t, err)

	env := parseEnvelope(t, stdout)
	assert.Empty(t, env.Backend, "pre-keyring failure must leave backend empty")
	assert.False(t, env.Written)
	assert.Contains(t, env.Error, "unsupported --key")
	assert.Contains(t, env.Error, "api_key")

	assert.Empty(t, stderr.String())
	assert.NotContains(t, stdout.String()+stderr.String(), secretSentinel)
}

func TestSetCredential_JSONFailure_MissingRefNoConfig_PreKeyring(t *testing.T) {
	testutil.Setup(t)
	stdout, stderr, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--key", "api_key", "--stdin", "--json")
	require.Error(t, err)

	env := parseEnvelope(t, stdout)
	assert.Empty(t, env.Ref)
	assert.Empty(t, env.Backend)
	assert.False(t, env.Written)
	assert.Contains(t, env.Error, "no config.yml found")
	assert.Contains(t, env.Error, "newrelic-cli/default")

	assert.Empty(t, stderr.String())
}

func TestSetCredential_JSONFailure_BothStdinAndEnv_PreKeyring(t *testing.T) {
	testutil.Setup(t)
	t.Setenv("NRQ_TEST_VAR", "ignored-value")
	stdout, stderr, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin", "--from-env", "NRQ_TEST_VAR", "--json")
	require.Error(t, err)

	env := parseEnvelope(t, stdout)
	assert.False(t, env.Written)
	assert.Contains(t, env.Error, "exactly one")
	assert.Empty(t, stderr.String(), "SilenceErrors must keep stderr empty on --json pre-keyring failure")
}

// --- --ref strict defaulting tests ------------------------------------------

func TestSetCredential_RefDefaulting_NoConfigOmittedFails(t *testing.T) {
	testutil.Setup(t)
	_, _, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--key", "api_key", "--stdin")
	require.Error(t, err)
	combined := err.Error()
	assert.Contains(t, combined, "--ref")
	assert.Contains(t, combined, "newrelic-cli/default")
}

func TestSetCredential_RefDefaulting_ConfigExistsUsesActive(t *testing.T) {
	testutil.Setup(t)
	// Write a config.yml with a non-default credential_ref.
	c := &config.Config{CredentialRef: "newrelic-cli/custom"}
	require.NoError(t, c.Save())

	_, _, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--key", "api_key", "--stdin")
	require.NoError(t, err)

	// Verify the secret landed in the active ref's bundle — not just that
	// the right ref was opened, but that the key was actually written.
	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	assert.Equal(t, "newrelic-cli/custom", st.Ref())
	assert.True(t, st.HasAPIKey(), "active ref's bundle must have received the key")
}

func TestSetCredential_RefDefaulting_ExplicitWins(t *testing.T) {
	testutil.Setup(t)
	c := &config.Config{CredentialRef: "newrelic-cli/from-config"}
	require.NoError(t, c.Save())

	_, _, err := runSetCredentialViaRoot(t,
		secretSentinel+"\n",
		"--ref", "newrelic-cli/explicit", "--key", "api_key", "--stdin")
	require.NoError(t, err)

	// The explicit --ref should win over the config's credential_ref.
	// Probe the explicit bundle directly via OpenRef.
	st, err := keychain.OpenRef("newrelic-cli/explicit")
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	assert.True(t, st.HasAPIKey(), "explicit --ref bundle must have received the key")
}

// --- §1.12 secret-leak audit across every failure path ---------------------

func TestSetCredential_NeverEmitsSecret_AcrossAllPaths(t *testing.T) {
	// Exhaustive: every failure case + the success case. The sentinel
	// must not appear in stdout or stderr regardless of --json setting.
	cases := []struct {
		name string
		args []string
		seed func(t *testing.T)
	}{
		{
			name: "invalid_key",
			args: []string{"--ref", "newrelic-cli/test", "--key", "bogus", "--stdin"},
		},
		{
			name: "invalid_key_json",
			args: []string{"--ref", "newrelic-cli/test", "--key", "bogus", "--stdin", "--json"},
		},
		{
			name: "missing_ref_no_config",
			args: []string{"--key", "api_key", "--stdin"},
		},
		{
			name: "missing_ref_no_config_json",
			args: []string{"--key", "api_key", "--stdin", "--json"},
		},
		{
			name: "both_stdin_and_env",
			args: []string{"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin", "--from-env", "FOO"},
			seed: func(t *testing.T) { t.Setenv("FOO", "ignored") },
		},
		{
			name: "existing_key",
			args: []string{"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin"},
			seed: func(t *testing.T) {
				// Pre-seed via OpenRef so the next set-credential fails no-clobber.
				st, err := keychain.OpenRef("newrelic-cli/test")
				require.NoError(t, err)
				require.NoError(t, st.SetAPIKey("NRAK-existing-12345"))
				require.NoError(t, st.Close())
			},
		},
		{
			name: "existing_key_json",
			args: []string{"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin", "--json"},
			seed: func(t *testing.T) {
				st, err := keychain.OpenRef("newrelic-cli/test")
				require.NoError(t, err)
				require.NoError(t, st.SetAPIKey("NRAK-existing-12345"))
				require.NoError(t, st.Close())
			},
		},
		{
			name: "success_human",
			args: []string{"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin"},
		},
		{
			name: "success_json",
			args: []string{"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin", "--json"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			testutil.Setup(t)
			if tc.seed != nil {
				tc.seed(t)
			}
			stdout, stderr, _ := runSetCredentialViaRoot(t, secretSentinel+"\n", tc.args...)
			combined := stdout.String() + stderr.String()
			assert.NotContains(t, combined, secretSentinel,
				"case %q: secret leaked to stdout or stderr", tc.name)
		})
	}
}

// --- Root-flag position invariance (Codex Major fix) ----------------------

// TestSetCredential_RootDeprecatedJSONBeforeSubcommand_AlsoEmitsEnvelope
// covers the deprecated root `--json` boolean variant of the same fix —
// root.go:146 registers it as a deprecated alias, and `nrq --json
// set-credential ...` must trigger the envelope path too.
func TestSetCredential_RootDeprecatedJSONBeforeSubcommand_AlsoEmitsEnvelope(t *testing.T) {
	testutil.Setup(t)
	rootCmd, opts := root.NewRootCmd()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	opts.Stdout, opts.Stderr = stdout, stderr
	opts.Stdin = strings.NewReader(secretSentinel + "\n")
	root.RegisterAll(rootCmd, opts, Register)
	// Deprecated root --json BEFORE the subcommand.
	rootCmd.SetArgs([]string{"--json", "set-credential",
		"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin"})
	require.NoError(t, rootCmd.Execute())

	env := parseEnvelope(t, stdout)
	assert.True(t, env.Written)
	assert.NotEmpty(t, env.Backend)
	// Stderr may contain cobra's deprecation notice for --json — that's a
	// general nrq warning surface, not a set-credential failure. The §1.12
	// invariant only forbids the secret value itself.
	assert.NotContains(t, stdout.String()+stderr.String(), secretSentinel)
}

// TestSetCredential_RootJSONBeforeSubcommand_AlsoEmitsEnvelope guards the
// fix for the order-dependence bug: `nrq -o json set-credential ...` (root
// flag before the subcommand) must emit the envelope and silence stderr,
// same as `nrq set-credential --json ...`. Without the o.Output == "json"
// normalization in the RunE wrapper, the two forms diverge silently.
func TestSetCredential_RootJSONBeforeSubcommand_AlsoEmitsEnvelope(t *testing.T) {
	testutil.Setup(t)
	rootCmd, opts := root.NewRootCmd()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	opts.Stdout, opts.Stderr = stdout, stderr
	opts.Stdin = strings.NewReader(secretSentinel + "\n")
	root.RegisterAll(rootCmd, opts, Register)
	// Root --output BEFORE the subcommand.
	rootCmd.SetArgs([]string{"-o", "json", "set-credential",
		"--ref", "newrelic-cli/test", "--key", "api_key", "--stdin"})
	require.NoError(t, rootCmd.Execute())

	env := parseEnvelope(t, stdout)
	assert.True(t, env.Written)
	assert.Equal(t, "newrelic-cli/test", env.Ref)
	assert.NotEmpty(t, env.Backend)
	assert.Empty(t, stderr.String(), "root --output json must trigger SilenceErrors path too")
	assert.NotContains(t, stdout.String()+stderr.String(), secretSentinel)
}
