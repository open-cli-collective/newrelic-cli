// MON-5373 dual-probe tests: the §1.8 migrator must enumerate the plaintext
// credentials file at BOTH the old hand-rolled location AND the new
// statedir-resolved canonical location. These exercise the matrix through
// the package-level `credentialFileCandidates` seam so Linux CI sees the
// macOS/Windows divergent layout (where statedir's resolver collapses old≡new
// the seam injects synthetic distinct paths instead).
package keychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/newrelic-cli/internal/testutil"
)

func withSyntheticCandidates(t *testing.T) (oldPath, newPath string) {
	t.Helper()
	tmp := testutil.Setup(t)
	oldDir := filepath.Join(tmp, "synthetic-old", "newrelic-cli")
	newDir := filepath.Join(tmp, "synthetic-new", "newrelic-cli")
	require.NoError(t, os.MkdirAll(oldDir, 0o700))
	require.NoError(t, os.MkdirAll(newDir, 0o700))
	oldPath = filepath.Join(oldDir, "credentials")
	newPath = filepath.Join(newDir, "credentials")

	prev := credentialFileCandidates
	credentialFileCandidates = func() ([]string, error) {
		return []string{oldPath, newPath}, nil
	}
	t.Cleanup(func() { credentialFileCandidates = prev })
	return oldPath, newPath
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// Old-only: only the pre-port hand-rolled location holds a credentials file.
func TestDiscover_DualProbe_OldOnly(t *testing.T) {
	oldPath, _ := withSyntheticCandidates(t)
	writeFile(t, oldPath, "api_key=NRAK-old-only\naccount_id=42\n")

	d, err := discover()
	require.NoError(t, err)
	require.Len(t, d.secrets, 1)
	assert.Equal(t, "NRAK-old-only", d.secrets[0].value)
	assert.Contains(t, d.secrets[0].location, oldPath)
}

// New-only: only the post-port canonical (Dir() + "credentials") holds one.
func TestDiscover_DualProbe_NewOnly(t *testing.T) {
	_, newPath := withSyntheticCandidates(t)
	writeFile(t, newPath, "api_key=NRAK-new-only\n")

	d, err := discover()
	require.NoError(t, err)
	require.Len(t, d.secrets, 1)
	assert.Equal(t, "NRAK-new-only", d.secrets[0].value)
	assert.Contains(t, d.secrets[0].location, newPath)
}

// Both equal on the parsed projection: BOTH files contribute, BOTH deleters
// are added so a successful migration scrubs both files.
func TestDiscover_DualProbe_BothEqual_DeletesBoth(t *testing.T) {
	oldPath, newPath := withSyntheticCandidates(t)
	writeFile(t, oldPath, "api_key=NRAK-equal-007\naccount_id=42\n")
	writeFile(t, newPath, "api_key=NRAK-equal-007\naccount_id=42\n")

	d, err := discover()
	require.NoError(t, err)

	var deletePaths []string
	for _, del := range d.deleters {
		deletePaths = append(deletePaths, del.label)
	}
	joined := strings.Join(deletePaths, "|")
	assert.Contains(t, joined, oldPath, "old path must be in deleter set")
	assert.Contains(t, joined, newPath, "new path must be in deleter set")
}

// Divergent on api_key → fail loud, mutate nothing.
func TestDiscover_DualProbe_Divergent_FailsLoud(t *testing.T) {
	oldPath, newPath := withSyntheticCandidates(t)
	writeFile(t, oldPath, "api_key=NRAK-old-divergent\n")
	writeFile(t, newPath, "api_key=NRAK-new-divergent\n")

	_, err := discover()
	require.Error(t, err, "divergent legacy credentials must fail loud")
	assert.Contains(t, err.Error(), "diverge")

	// Both files must be untouched after fail-loud.
	_, statErr := os.Stat(oldPath)
	assert.NoError(t, statErr, "old file must remain after fail-loud")
	_, statErr = os.Stat(newPath)
	assert.NoError(t, statErr, "new file must remain after fail-loud")
}

// Divergent on a non-secret field (account_id) → also fails loud.
func TestDiscover_DualProbe_Divergent_NonSecret_FailsLoud(t *testing.T) {
	oldPath, newPath := withSyntheticCandidates(t)
	writeFile(t, oldPath, "api_key=NRAK-shared\naccount_id=11\n")
	writeFile(t, newPath, "api_key=NRAK-shared\naccount_id=22\n")

	_, err := discover()
	require.Error(t, err, "divergent non-secret field must also fail loud")
	assert.Contains(t, err.Error(), "diverge")
}
