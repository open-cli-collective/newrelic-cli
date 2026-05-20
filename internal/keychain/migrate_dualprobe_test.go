// MON-5373 dual-probe tests: the §1.8 migrator must enumerate the plaintext
// credentials file at BOTH the old hand-rolled location AND the new
// statedir-resolved canonical location (the file lives in the same dir as
// config.yml, so the resolver switch relocates it). On Linux these collapse
// to one path; on macOS/Windows they diverge and both must be discovered.
package keychain

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

func writeLegacyAt(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// Old-only: only the pre-port hand-rolled location holds a credentials file.
func TestDiscover_DualProbe_OldOnly(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux: old==new; dual-probe collapses")
	}
	testutil.Setup(t)
	writeLegacyAt(t, testutil.LegacyCredentialsPath(t),
		"api_key=NRAK-old-only\naccount_id=42\n")

	d, err := discover()
	require.NoError(t, err)
	require.Len(t, d.secrets, 1)
	assert.Equal(t, "NRAK-old-only", d.secrets[0].value)
	assert.Contains(t, d.secrets[0].location, testutil.LegacyCredentialsPath(t))
}

// New-only: only the post-port canonical (Dir() + "credentials") holds one.
func TestDiscover_DualProbe_NewOnly(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux: old==new; dual-probe collapses")
	}
	testutil.Setup(t)
	canonical, err := config.CanonicalCredentialsPath()
	require.NoError(t, err)
	writeLegacyAt(t, canonical, "api_key=NRAK-new-only\n")

	d, err := discover()
	require.NoError(t, err)
	require.Len(t, d.secrets, 1)
	assert.Equal(t, "NRAK-new-only", d.secrets[0].value)
	assert.Contains(t, d.secrets[0].location, canonical)
}

// Both equal on the parsed projection: migrate from one source set; both
// deleters are added so a successful migration scrubs both files.
func TestDiscover_DualProbe_BothEqual_DeletesBoth(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux: old==new; collapses to one")
	}
	testutil.Setup(t)
	oldPath := testutil.LegacyCredentialsPath(t)
	canonical, err := config.CanonicalCredentialsPath()
	require.NoError(t, err)
	writeLegacyAt(t, oldPath, "api_key=NRAK-equal-007\naccount_id=42\n")
	writeLegacyAt(t, canonical, "api_key=NRAK-equal-007\naccount_id=42\n")

	d, err := discover()
	require.NoError(t, err)
	// Both files contribute api_key + account_id — but the planner dedups by
	// value; what we assert here is that discovery surfaced both deleters.
	var deletePaths []string
	for _, del := range d.deleters {
		deletePaths = append(deletePaths, del.label)
	}
	joined := strings.Join(deletePaths, "|")
	assert.Contains(t, joined, oldPath, "old path must be in deleter set")
	assert.Contains(t, joined, canonical, "new path must be in deleter set")
}

// Divergent on api_key → fail loud, mutate nothing.
func TestDiscover_DualProbe_Divergent_FailsLoud(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux: old==new; collapses to one")
	}
	testutil.Setup(t)
	oldPath := testutil.LegacyCredentialsPath(t)
	canonical, err := config.CanonicalCredentialsPath()
	require.NoError(t, err)
	writeLegacyAt(t, oldPath, "api_key=NRAK-old-divergent\n")
	writeLegacyAt(t, canonical, "api_key=NRAK-new-divergent\n")

	_, err = discover()
	require.Error(t, err, "divergent legacy credentials must fail loud")
	assert.Contains(t, err.Error(), "diverge")
	// Both files must be untouched.
	_, statErr := os.Stat(oldPath)
	assert.NoError(t, statErr, "old file must remain after fail-loud")
	_, statErr = os.Stat(canonical)
	assert.NoError(t, statErr, "new file must remain after fail-loud")
}
