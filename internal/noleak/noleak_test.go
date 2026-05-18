// Package noleak holds nrq's §1.12 / §1.11 acceptance suite: it drives the
// REAL entrypoint (root.NewRootCmd) and asserts the API-key secret never
// appears in stdout, stderr, config.yml, or the JSON _migration block, that
// runtime resolution is keyring-only (no env), and that the one-time §1.8
// signal fires exactly once on the real command path (§1.11.6).
package noleak_test

import (
	"bytes"
	"errors"
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
	"github.com/open-cli-collective/newrelic-cli/internal/output"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

const sentinel = "NRAK-SUPERSECRETSENTINEL-do-not-leak"

// probeRegister adds hidden commands that go through the REAL lazy
// chokepoint `opts.APIClient()` (which opens the keyring and runs the §1.8
// migration) — exactly what an API command does, minus the network call. So
// these exercise the single-chokepoint architecture, not a bypass.
//
//	__probe      success path: resolve client, emit JSON via the real view.
//	__probefail  resolve client (migration runs), then return a non-zero
//	             error — the §1.11.6 "signal survives a non-zero exit" case.
func probeRegister(rootCmd *cobra.Command, opts *root.Options) {
	rootCmd.AddCommand(&cobra.Command{
		Use:    "__probe",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := opts.APIClient(); err != nil {
				return err
			}
			return opts.View().JSON(map[string]string{"ok": "true"})
		},
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:    "__probefail",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := opts.APIClient(); err != nil {
				return err
			}
			return errors.New("boom: command failed after a successful migration")
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
	// Mirror cmd/nrq/main.go EXACTLY: on a non-zero exit, flush any pending
	// §1.8 block before the process would os.Exit. This is the real
	// entrypoint contract under test (§1.11.6).
	if err != nil {
		output.FlushMigrationJSONOnError(&out)
	}
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

// §1.11 item 2 (real chokepoint): a runtime API command resolves through
// opts.APIClient(). With NEWRELIC_API_KEY set in the environment but nothing
// in the keyring, resolution MUST fail (the env var is not a credential
// source) — proving runtime is keyring-only.
func TestRuntime_APIClient_IgnoresAPIKeyEnv(t *testing.T) {
	testutil.Setup(t)
	t.Setenv("NEWRELIC_API_KEY", sentinel) // present in env, never ingested
	out, errOut, err := run(t, "__probe")
	require.Error(t, err, "APIClient must not accept NEWRELIC_API_KEY as a source")
	assert.True(t, errors.Is(err, keychain.ErrMissingAPIKey))
	assert.NotContains(t, out+errOut, sentinel)
}

// §1.11.6: the one-time signal SURVIVES a non-zero exit. Migration succeeds
// inside opts.APIClient(); the command then fails. The real entrypoint must
// still emit _migration (flushed on the error path) — and never the value.
func TestMigrationSignal_SurvivesNonZeroExit(t *testing.T) {
	tmp := testutil.Setup(t)
	plantLegacyFile(t, tmp)
	out, _, err := run(t, "__probefail", "-o", "json")
	require.Error(t, err, "__probefail must exit non-zero")
	assert.Contains(t, out, `"_migration"`, "signal must survive a non-zero exit")
	assert.Contains(t, out, `"api_key"`)
	assert.NotContains(t, out, sentinel)
}

// §1.5/§1.11 (Blocker): an existing keyring value is never silently
// clobbered. Second set-credential without --overwrite fails; with
// --overwrite it replaces.
func TestSetCredential_NoClobberByDefault(t *testing.T) {
	testutil.Setup(t)
	setCred := func(val string, extra ...string) (string, error) {
		rootCmd, opts := root.NewRootCmd()
		var o, e bytes.Buffer
		opts.Stdout, opts.Stderr = &o, &e
		opts.Stdin = strings.NewReader(val + "\n")
		root.RegisterAll(rootCmd, opts, configcmd.Register)
		rootCmd.SetArgs(append([]string{"set-credential", "--ref", "newrelic-cli/default", "--key", "api_key", "--stdin"}, extra...))
		return o.String() + e.String(), rootCmd.Execute()
	}
	const k1, k2, k3 = "NRAK-first-0000000001", "NRAK-second-000000002", "NRAK-third-0000000003"
	_, err := setCred(k1)
	require.NoError(t, err)

	out, err := setCred(k2)
	require.Error(t, err, "second set without --overwrite must refuse")
	assert.Contains(t, out+errStr(err), "overwrite")
	assert.NotContains(t, out, k2)

	_, err = setCred(k3, "--overwrite")
	require.NoError(t, err, "--overwrite must replace")

	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	got, err := st.APIKey()
	require.NoError(t, err)
	assert.Equal(t, k3, got)
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// §1.8/§2.5 (Blocker): if a legacy original cannot be removed, the migration
// returns an error, emits NO signal, and leaves the legacy file in place for
// a retry — it must never claim "one-time operation" with plaintext still on
// disk.
func TestMigration_CleanupFailure_NoSignal_FileRetained(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write perms")
	}
	tmp := testutil.Setup(t)
	dir := filepath.Join(tmp, ".config", "newrelic-cli")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	legacy := filepath.Join(dir, "credentials")
	require.NoError(t, os.WriteFile(legacy, []byte("api_key="+sentinel+"\n"), 0o600))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))
	// Make the containing dir non-writable so os.Remove(legacy) fails.
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	out, errOut, err := run(t, "__probe", "-o", "json")
	require.Error(t, err, "migration must fail when it cannot complete (config save or legacy scrub)")
	assert.NotContains(t, out, `"_migration"`, "no signal on an incomplete migration")
	assert.NotContains(t, errOut, "one-time operation")
	assert.NotContains(t, out+errOut, sentinel)
	_, statErr := os.Stat(legacy)
	assert.NoError(t, statErr, "legacy file must remain for a retry")
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

// M1: --from-env ingress for set-credential — value lands in the keyring,
// never echoed; empty/unset var is a hard error (no silent empty key).
func TestSetCredential_FromEnvIngress(t *testing.T) {
	testutil.Setup(t)
	t.Setenv("NRQ_INGRESS_VAR", sentinel)
	rootCmd, opts := root.NewRootCmd()
	var o, e bytes.Buffer
	opts.Stdout, opts.Stderr = &o, &e
	root.RegisterAll(rootCmd, opts, configcmd.Register)
	rootCmd.SetArgs([]string{"set-credential", "--ref", "newrelic-cli/default", "--key", "api_key", "--from-env", "NRQ_INGRESS_VAR"})
	require.NoError(t, rootCmd.Execute())
	assert.NotContains(t, o.String()+e.String(), sentinel)

	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	got, err := st.APIKey()
	require.NoError(t, err)
	assert.Equal(t, sentinel, got)

	// Empty/unset env var must fail loudly, not store an empty key.
	rootCmd2, opts2 := root.NewRootCmd()
	var o2, e2 bytes.Buffer
	opts2.Stdout, opts2.Stderr = &o2, &e2
	root.RegisterAll(rootCmd2, opts2, configcmd.Register)
	rootCmd2.SetArgs([]string{"set-credential", "--ref", "newrelic-cli/default", "--key", "api_key", "--from-env", "NRQ_UNSET_VAR", "--overwrite"})
	require.Error(t, rootCmd2.Execute(), "empty/unset --from-env var must fail")
}

// M1: init --api-key-from-env ingress; value never echoed, not in config.yml.
func TestInit_FromEnvIngress(t *testing.T) {
	testutil.Setup(t)
	t.Setenv("NRQ_INGRESS_VAR", sentinel)
	rootCmd, opts := root.NewRootCmd()
	var o, e bytes.Buffer
	opts.Stdout, opts.Stderr = &o, &e
	root.RegisterAll(rootCmd, opts, initcmd.Register)
	rootCmd.SetArgs([]string{"init", "--api-key-from-env", "NRQ_INGRESS_VAR", "--account-id", "42", "--no-verify"})
	require.NoError(t, rootCmd.Execute())
	assert.NotContains(t, o.String()+e.String(), sentinel)
	raw, _ := os.ReadFile(config.Path())
	assert.NotContains(t, string(raw), sentinel)

	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	got, _ := st.APIKey()
	assert.Equal(t, sentinel, got)
}

// L3: init --overwrite scripted ingress replaces an existing keyring value
// end-to-end (the explicit-intent path), value never echoed.
func TestInit_OverwriteScriptedIngress(t *testing.T) {
	testutil.Setup(t)
	st0, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	require.NoError(t, st0.SetAPIKey("NRAK-existing-000001"))
	_ = st0.Close()

	rootCmd, opts := root.NewRootCmd()
	var o, e bytes.Buffer
	opts.Stdout, opts.Stderr = &o, &e
	opts.Stdin = strings.NewReader(sentinel + "\n")
	root.RegisterAll(rootCmd, opts, initcmd.Register)
	rootCmd.SetArgs([]string{"init", "--api-key-stdin", "--overwrite", "--no-verify"})
	require.NoError(t, rootCmd.Execute())
	assert.NotContains(t, o.String()+e.String(), sentinel)

	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	got, _ := st.APIKey()
	assert.Equal(t, sentinel, got, "--overwrite must replace the existing key")
}

// M3: config clear --dry-run reports without changing anything; --all also
// removes config.yml; both are idempotent and non-interactive.
func TestConfigClear_DryRunAndAll(t *testing.T) {
	testutil.Setup(t)
	st0, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	require.NoError(t, st0.SetAPIKey("NRAK-clear-00000001"))
	_ = st0.Close()
	cfg := &config.Config{CredentialRef: "newrelic-cli/default", AccountID: "42"}
	require.NoError(t, cfg.Save())

	out, _, err := run(t, "config", "clear", "--dry-run", "--all")
	require.NoError(t, err)
	assert.Contains(t, out, "would remove")
	// Dry-run changed nothing.
	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	assert.True(t, st.HasAPIKey(), "dry-run must not delete")
	_ = st.Close()
	_, statErr := os.Stat(config.Path())
	require.NoError(t, statErr, "dry-run must not remove config.yml")

	_, _, err = run(t, "config", "clear", "--all")
	require.NoError(t, err)
	st2, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	assert.False(t, st2.HasAPIKey())
	_ = st2.Close()
	_, statErr = os.Stat(config.Path())
	assert.True(t, os.IsNotExist(statErr), "--all removes config.yml")

	// Idempotent: a second clear --all still exits 0.
	_, _, err = run(t, "config", "clear", "--all")
	assert.NoError(t, err, "clear is idempotent")
}

// L1: `config show -o json` reports api_key presence as a bool and never the
// value (secret-absence pinned for the JSON surface).
func TestConfigShow_JSON_NoSecretValue(t *testing.T) {
	testutil.Setup(t)
	st0, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	require.NoError(t, st0.SetAPIKey(sentinel))
	_ = st0.Close()

	out, _, err := run(t, "config", "show", "-o", "json")
	require.NoError(t, err)
	assert.Contains(t, out, `"api_key_present": true`)
	assert.NotContains(t, out, sentinel, "config show JSON must never contain the value")
}

// An invalid --ref fails up front with an actionable message naming the
// flag — not deep inside OpenRef.
func TestSetCredential_InvalidRef_Actionable(t *testing.T) {
	testutil.Setup(t)
	rootCmd, opts := root.NewRootCmd()
	var o, e bytes.Buffer
	opts.Stdout, opts.Stderr = &o, &e
	opts.Stdin = strings.NewReader("NRAK-whatever-00001\n")
	root.RegisterAll(rootCmd, opts, configcmd.Register)
	rootCmd.SetArgs([]string{"set-credential", "--ref", "no-slash-here", "--key", "api_key", "--stdin"})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error()+o.String()+e.String(), "--ref")
}

// A secret-only init (no account-id/region, non-interactive, no prior
// config.yml) must NOT create config.yml just to restate the default ref.
func TestInit_SecretOnly_NoConfigYMLCreated(t *testing.T) {
	testutil.Setup(t)
	rootCmd, opts := root.NewRootCmd()
	var o, e bytes.Buffer
	opts.Stdout, opts.Stderr = &o, &e
	opts.Stdin = strings.NewReader(sentinel + "\n")
	root.RegisterAll(rootCmd, opts, initcmd.Register)
	rootCmd.SetArgs([]string{"init", "--api-key-stdin", "--no-verify"})
	require.NoError(t, rootCmd.Execute())

	_, statErr := os.Stat(config.Path())
	assert.True(t, os.IsNotExist(statErr),
		"secret-only init must not create config.yml")
	st, err := keychain.OpenNoMigrate()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	got, _ := st.APIKey()
	assert.Equal(t, sentinel, got)
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
