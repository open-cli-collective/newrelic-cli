// Package noleak holds nrq's §1.12 / §1.11 acceptance suite: it drives the
// REAL entrypoint (root.NewRootCmd) and asserts the API-key secret never
// appears in stdout, stderr, config.yml, or the JSON _migration block, that
// runtime resolution is keyring-only (no env), and that the one-time §1.8
// signal fires exactly once on the real command path (§1.11.6).
package noleak_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/configcmd"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/initcmd"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

const sentinel = "NRAK-SUPERSECRETSENTINEL-do-not-leak"

// probeRegister adds a hidden `__probe` command that triggers the §1.8
// migration (keychain.Open) and then emits JSON through the real view — the
// minimal stand-in for an API command, so the §1.11.6 test exercises the
// real entrypoint + migration + JSON splice without a network call.
func probeRegister(rootCmd *cobra.Command, opts *root.Options) {
	rootCmd.AddCommand(&cobra.Command{
		Use:    "__probe",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := keychain.Open()
			if err != nil {
				return err
			}
			_ = st.Close()
			return opts.View().JSON(map[string]string{"ok": "true"})
		},
	})
}

// run drives the real entrypoint with args, capturing stdout, the cobra
// error writer, AND the process os.Stderr (the §1.8 migration signal is
// written there by design — it must reach the real terminal even when the
// command's view writer is redirected, §1.11.6).
func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	rootCmd, opts := root.NewRootCmd()
	var out, errb bytes.Buffer
	opts.Stdout, opts.Stderr = &out, &errb
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	root.RegisterAll(rootCmd, opts, configcmd.Register, initcmd.Register, probeRegister)
	rootCmd.SetArgs(args)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	err := rootCmd.Execute()
	_ = w.Close()
	os.Stderr = origStderr
	var pipeBuf bytes.Buffer
	_, _ = pipeBuf.ReadFrom(r)

	return out.String(), errb.String() + pipeBuf.String(), err
}

func plantLegacyFile(t *testing.T, tmp string) {
	t.Helper()
	dir := filepath.Join(tmp, ".config", "newrelic-cli")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "credentials"),
		[]byte("api_key="+sentinel+"\naccount_id=42\nregion=EU\n"), 0o600))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))
}

// §1.12: the secret never appears in any human-facing surface or config.yml.
func TestNoLeak_ShowAndConfigFile(t *testing.T) {
	tmp := testutil.Setup(t)
	plantLegacyFile(t, tmp)

	// Trigger migration via the probe (api_key -> keyring).
	_, _, err := run(t, "__probe", "-o", "json")
	require.NoError(t, err)

	out, errOut, err := run(t, "config", "show")
	require.NoError(t, err)
	assert.NotContains(t, out, sentinel)
	assert.NotContains(t, errOut, sentinel)

	raw, _ := os.ReadFile(config.Path())
	assert.NotContains(t, string(raw), sentinel, "secret must never be in config.yml")
}

// §1.11.6: the one-time signal fires exactly once on the real JSON path and
// is absent on the next run; the secret value is never in the block.
func TestMigrationSignal_JSON_OnceOnly(t *testing.T) {
	tmp := testutil.Setup(t)
	plantLegacyFile(t, tmp)

	out1, _, err := run(t, "__probe", "-o", "json")
	require.NoError(t, err)
	assert.Contains(t, out1, `"_migration"`)
	assert.Contains(t, out1, `"api_key"`)
	assert.Contains(t, out1, "config:")   // non-secret moves signaled too (§1.8)
	assert.NotContains(t, out1, sentinel) // never the value

	out2, _, err := run(t, "__probe", "-o", "json")
	require.NoError(t, err)
	assert.NotContains(t, out2, `"_migration"`, "signal must not repeat")
}

// §1.11.6 text path + survives a non-zero exit downstream.
func TestMigrationSignal_TextStderr(t *testing.T) {
	tmp := testutil.Setup(t)
	plantLegacyFile(t, tmp)
	_, errOut, err := run(t, "__probe")
	require.NoError(t, err)
	assert.Contains(t, errOut, "migrated api_key to keyring")
	assert.Contains(t, errOut, "migrated account_id to config")
	assert.Contains(t, errOut, "migrated region to config")
	assert.NotContains(t, errOut, sentinel)
}

// §1.11 item 2: runtime resolution is keyring-only — NEWRELIC_API_KEY is not
// read at runtime (it is ingress-only).
func TestRuntime_IgnoresAPIKeyEnv(t *testing.T) {
	testutil.Setup(t)
	t.Setenv("NEWRELIC_API_KEY", sentinel) // present in env, but not ingested
	out, errOut, err := run(t, "config", "show")
	require.NoError(t, err)
	assert.Contains(t, out, "API key:        not set",
		"runtime must not treat NEWRELIC_API_KEY as a credential source")
	assert.NotContains(t, out+errOut, sentinel)
}

// §1.5 / §2.5: `config set-api-key` accepts no value by ANY path — positional,
// flag, or no-arg — and always exits nonzero pointing at the migration path.
func TestSetAPIKey_HardDeprecated_EveryPath(t *testing.T) {
	testutil.Setup(t)
	for _, args := range [][]string{
		{"config", "set-api-key"},
		{"config", "set-api-key", sentinel},
		{"config", "set-api-key", "--api-key", sentinel},
		{"config", "set-api-key", "--api-key=" + sentinel},
	} {
		out, errOut, err := run(t, args...)
		require.Error(t, err, "args=%v must fail", args)
		assert.Contains(t, errOut+out, "set-credential")
		assert.NotContains(t, errOut+out, sentinel, "args=%v leaked the value", args)
	}
}

// §1.5.2: set-credential ingests via stdin (never a flag/positional) and
// resolution then returns it; config.yml stays secret-free.
func TestSetCredential_StdinIngress(t *testing.T) {
	testutil.Setup(t)
	rootCmd, opts := root.NewRootCmd()
	var out, errb bytes.Buffer
	opts.Stdout, opts.Stderr = &out, &errb
	opts.Stdin = strings.NewReader(sentinel + "\n")
	root.RegisterAll(rootCmd, opts, configcmd.Register)
	rootCmd.SetArgs([]string{"set-credential", "--ref", "newrelic-cli/default", "--key", "api_key", "--stdin"})
	require.NoError(t, rootCmd.Execute())

	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	got, err := st.APIKey()
	require.NoError(t, err)
	assert.Equal(t, sentinel, got)
	assert.NotContains(t, out.String()+errb.String(), sentinel)
}

// §1.11 item 1: init writes no secret field to config.yml.
func TestInit_NoSecretInConfigYML(t *testing.T) {
	testutil.Setup(t)
	rootCmd, opts := root.NewRootCmd()
	var out, errb bytes.Buffer
	opts.Stdout, opts.Stderr = &out, &errb
	opts.Stdin = strings.NewReader(sentinel + "\n")
	root.RegisterAll(rootCmd, opts, initcmd.Register)
	rootCmd.SetArgs([]string{"init", "--api-key-stdin", "--account-id", "42", "--region", "US", "--no-verify"})
	require.NoError(t, rootCmd.Execute())

	raw, err := os.ReadFile(config.Path())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), sentinel)
	assert.Contains(t, string(raw), "account_id: \"42\"")
}
