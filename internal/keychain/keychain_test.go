package keychain_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

func TestAdapter_RoundTrip(t *testing.T) {
	testutil.Setup(t)
	st, err := keychain.Open()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	assert.False(t, st.HasAPIKey())
	_, err = st.APIKey()
	assert.True(t, errors.Is(err, keychain.ErrMissingAPIKey))

	require.NoError(t, st.SetAPIKey("NRAK-roundtrip"))
	assert.True(t, st.HasAPIKey())
	got, err := st.APIKey()
	require.NoError(t, err)
	assert.Equal(t, "NRAK-roundtrip", got)

	require.NoError(t, st.DeleteAPIKey())
	assert.False(t, st.HasAPIKey())
	require.NoError(t, st.DeleteAPIKey(), "delete is idempotent (§1.7)")

	assert.Equal(t, "newrelic-cli/default", st.Ref())
}

// Adapter-level no-empty write guard (#6): the public setter rejects an
// empty value rather than creating a corrupted entry.
func TestSetAPIKey_RejectsEmpty(t *testing.T) {
	testutil.Setup(t)
	st, err := keychain.Open()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	err = st.SetAPIKey("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
	assert.False(t, st.HasAPIKey(), "rejected write must not create an entry")
}

func TestAdapter_Clear(t *testing.T) {
	testutil.Setup(t)
	st, err := keychain.Open()
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	require.NoError(t, st.SetAPIKey("NRAK-x"))
	_, err = st.Clear()
	require.NoError(t, err)
	assert.False(t, st.HasAPIKey())
}

func TestOpen_UnknownBackend_FailsClosed(t *testing.T) {
	testutil.Setup(t)
	// An explicit invalid backend in config.yml must fail closed, never
	// silently auto-select.
	c := &config.Config{CredentialRef: "newrelic-cli/default"}
	c.Keyring.Backend = "bogus"
	require.NoError(t, c.Save())
	// Neutralize the test env backend so config.yml's bogus value is what's
	// exercised. Empty is equivalent to unset for backend selection (both
	// defer to config.yml); t.Setenv restores it deterministically at
	// teardown, so no manual os.Unsetenv (which would contradict the
	// t.Setenv-registered cleanup) is needed.
	t.Setenv("NEWRELIC_CLI_KEYRING_BACKEND", "")

	_, err := keychain.OpenNoMigrate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid keyring.backend")
}

func TestOpenRef_OverridesConfiguredRef(t *testing.T) {
	testutil.Setup(t)
	st, err := keychain.OpenRef("newrelic-cli/other")
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	assert.Equal(t, "newrelic-cli/other", st.Ref())
}

// §1.8 end-to-end: a legacy plaintext credentials file is migrated — api_key
// to the keyring, account_id/region folded into config.yml, the legacy file
// scrubbed — on the first Open().
func TestMigration_LegacyFile_EndToEnd(t *testing.T) {
	tmp := testutil.Setup(t)
	legacyDir := filepath.Join(tmp, ".config", "newrelic-cli")
	require.NoError(t, os.MkdirAll(legacyDir, 0o700))
	legacy := filepath.Join(legacyDir, "credentials")
	require.NoError(t, os.WriteFile(legacy,
		[]byte("api_key=NRAK-legacy\naccount_id=42\nregion=EU\n"), 0o600))
	// discover() uses ~/.config (HOME), not XDG; point XDG at HOME so
	// config.yml lands beside it deterministically for the assertion.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))

	st, err := keychain.Open() // runs the one-time migration
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	got, err := st.APIKey()
	require.NoError(t, err)
	assert.Equal(t, "NRAK-legacy", got)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "42", cfg.AccountID)
	assert.Equal(t, "EU", cfg.Region)

	_, statErr := os.Stat(legacy)
	assert.True(t, os.IsNotExist(statErr), "legacy file must be scrubbed after migration")

	raw, err := os.ReadFile(config.Path())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "NRAK-legacy", "secret must never land in config.yml")

	// Idempotent: a second Open finds nothing legacy and still works.
	st2, err := keychain.Open()
	require.NoError(t, err)
	defer func() { _ = st2.Close() }()
	v2, err := st2.APIKey()
	require.NoError(t, err)
	assert.Equal(t, "NRAK-legacy", v2)
}
