package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

func TestLoad_AbsentAppliesDefaultRef(t *testing.T) {
	testutil.Setup(t)
	c, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, config.DefaultCredentialRef, c.CredentialRef)
	assert.Equal(t, "newrelic-cli/default", c.CredentialRef)
}

func TestSaveLoad_RoundTrip_NoSecretField(t *testing.T) {
	testutil.Setup(t)
	c := &config.Config{CredentialRef: "newrelic-cli/default", AccountID: "12345", Region: "EU"}
	require.NoError(t, c.Save())

	cfgPath, err := config.Path()
	require.NoError(t, err)
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "api_key", "config.yml must never carry a secret field")

	got, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "12345", got.AccountID)
	assert.Equal(t, "EU", got.Region)
}

func TestResolveAccountID_Precedence(t *testing.T) {
	testutil.Setup(t)
	c := &config.Config{AccountID: "from-config"}

	v, src := c.ResolveAccountID()
	assert.Equal(t, "from-config", v)
	assert.Equal(t, config.SourceConfig, src)

	t.Setenv("NEWRELIC_ACCOUNT_ID", "from-env")
	v, src = c.ResolveAccountID()
	assert.Equal(t, "from-env", v, "env overrides config")
	assert.Equal(t, config.SourceEnv, src)

	empty := &config.Config{}
	t.Setenv("NEWRELIC_ACCOUNT_ID", "")
	_ = os.Unsetenv("NEWRELIC_ACCOUNT_ID")
	v, src = empty.ResolveAccountID()
	assert.Equal(t, "", v)
	assert.Equal(t, config.SourceUnset, src)
}

func TestResolveRegion_Precedence_DefaultUS(t *testing.T) {
	testutil.Setup(t)
	empty := &config.Config{}
	v, src := empty.ResolveRegion()
	assert.Equal(t, "US", v)
	assert.Equal(t, config.SourceUnset, src)

	c := &config.Config{Region: "eu"}
	v, src = c.ResolveRegion()
	assert.Equal(t, "EU", v, "region upper-cased")
	assert.Equal(t, config.SourceConfig, src)

	t.Setenv("NEWRELIC_REGION", "us")
	v, src = c.ResolveRegion()
	assert.Equal(t, "US", v)
	assert.Equal(t, config.SourceEnv, src)
}

// TestDir_StatedirContract verifies the cli-common statedir.Scope resolver
// is what backs config.Dir(): the path equals os.UserConfigDir()/newrelic-cli
// under the hermetic 7-var harness, is absolute, and sits under the hermetic
// root. (A behavioral round-trip alone would still pass if the hand-rolled
// resolver accidentally remained — Codex r1 catch.)
func TestDir_StatedirContract(t *testing.T) {
	tmp := testutil.Setup(t)
	dir, err := config.Dir()
	require.NoError(t, err)

	osCfg, err := os.UserConfigDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(osCfg, "newrelic-cli"), dir,
		"Dir() must equal os.UserConfigDir()/newrelic-cli — i.e. routed through cli-common/statedir")
	assert.True(t, filepath.IsAbs(dir), "Dir() must be absolute")
	assert.True(t, strings.HasPrefix(dir, tmp), "Dir() must sit under the hermetic root %q (got %q)", tmp, dir)

	// Save / Load round-trip + perm checks (no stale temp).
	c := &config.Config{CredentialRef: "newrelic-cli/default", AccountID: "42"}
	require.NoError(t, c.Save())

	di, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm(), "config dir must be 0700")

	cfgPath, err := config.Path()
	require.NoError(t, err)
	fi, err := os.Stat(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "config.yml must be 0600")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"),
			"no stale temp file should remain post-Save (got %s)", e.Name())
	}

	got, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "42", got.AccountID)
}
