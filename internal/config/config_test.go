package config_test

import (
	"os"
	"path/filepath"
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

	raw, err := os.ReadFile(config.Path())
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

func TestDir_XDGRespected(t *testing.T) {
	tmp := testutil.Setup(t)
	assert.Equal(t, filepath.Join(tmp, "xdgconfig", "newrelic-cli"), config.Dir())
}
