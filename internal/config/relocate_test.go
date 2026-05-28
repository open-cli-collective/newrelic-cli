// Package config relocation tests (§3.2 8-row matrix + LoadForRuntime
// soft-degrade contract). These use the unexported testable seams so
// production code paths are what the tests exercise — no parallel
// implementations (slck MON-5372 lesson).
package config

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/cli-common/statedirtest"
)

// setupRelocPair gives the relocation tests two GUARANTEED-DISTINCT dirs even
// on Linux (where statedir's resolver collapses old==new). The unexported
// seams (detectRelocation/loadFromNewDir) accept newDir as a parameter, so
// we can synthesize an "alternate canonical" dir under the hermetic root and
// exercise the macOS/Windows divergent layout on Linux CI. Without this,
// every relocation row would skip on the cheapest CI lane.
func setupRelocPair(t *testing.T) (oldDir, newDir string) {
	t.Helper()
	tmp := statedirtest.Hermetic(t)
	old, err := oldHandRolledConfigDir()
	require.NoError(t, err)

	// Synthetic distinct new-dir — anywhere outside oldDir. Using a sibling
	// of the hermetic root prevents accidental old-vs-new ambiguity.
	new := filepath.Join(tmp, "synthetic-statedir", "newrelic-cli")
	require.NoError(t, os.MkdirAll(old, 0o700))
	require.NoError(t, os.MkdirAll(new, 0o700))
	if old == new {
		t.Fatalf("setupRelocPair: synthetic newDir collided with oldDir: %s", old)
	}
	return old, new
}

func writeYAML(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// Row 1: new-only.
func TestRelocate_NewOnly_NoOp(t *testing.T) {
	_, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(new, configFileName), "credential_ref: newrelic-cli/default\n")

	got, err := detectRelocation(new)
	require.NoError(t, err)
	assert.Equal(t, relocNone, got.Kind)
	assert.False(t, got.CopyNeeded)

	cfg, err := loadFromNewDir(new)
	require.NoError(t, err)
	assert.Equal(t, "newrelic-cli/default", cfg.CredentialRef)
}

// Row 2: old-only well-formed.
func TestRelocate_OldOnly_CopyNeeded(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "credential_ref: newrelic-cli/legacy\naccount_id: \"42\"\n")

	got, err := detectRelocation(new)
	require.NoError(t, err)
	assert.Equal(t, relocOldOnly, got.Kind)
	assert.True(t, got.CopyNeeded)

	// Runtime fallback reads old without copying.
	cfg, err := loadFromNewDir(new)
	require.NoError(t, err)
	assert.Equal(t, "newrelic-cli/legacy", cfg.CredentialRef)
	assert.Equal(t, "42", cfg.AccountID)

	_, statErr := os.Stat(filepath.Join(new, configFileName))
	assert.True(t, os.IsNotExist(statErr), "Load must not write to new dir")
}

// Row 3: old-only malformed (must fail loud BEFORE CopyNeeded — MON-5371).
func TestRelocate_OldOnly_Malformed_FailsLoud(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "[unclosed_array: yes\n")

	got, err := detectRelocation(new)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRelocationConflict), "must wrap ErrRelocationConflict")
	assert.Equal(t, relocBothDivergent, got.Kind)
	assert.False(t, got.CopyNeeded, "must NOT set CopyNeeded on malformed-old — would propagate corrupt bytes to new dir")
}

// Row 4: both materially equal (defaults-applied).
func TestRelocate_BothEqual_DefaultOmittedVsExplicit_IsEqual(t *testing.T) {
	old, new := setupRelocPair(t)
	// Old omits credential_ref (defaults to DefaultCredentialRef); new is explicit.
	writeYAML(t, filepath.Join(old, configFileName), "account_id: \"42\"\n")
	writeYAML(t, filepath.Join(new, configFileName), "credential_ref: newrelic-cli/default\naccount_id: \"42\"\n")

	got, err := detectRelocation(new)
	require.NoError(t, err)
	assert.Equal(t, relocBothEqual, got.Kind)
	assert.False(t, got.CopyNeeded)
}

// Row 5: both, divergent → ErrRelocationConflict.
func TestRelocate_BothDivergent_Conflict(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "credential_ref: newrelic-cli/old\n")
	writeYAML(t, filepath.Join(new, configFileName), "credential_ref: newrelic-cli/new\n")

	got, err := detectRelocation(new)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRelocationConflict))
	assert.Equal(t, relocBothDivergent, got.Kind)
}

// Row 6: both, malformed-new — canonical unreadable; runtime hard-fail.
func TestRelocate_MalformedNew_HardFail(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "credential_ref: newrelic-cli/old\n")
	writeYAML(t, filepath.Join(new, configFileName), "[unclosed_array: yes\n")

	cfg, err := loadFromNewDir(new)
	require.Error(t, err, "malformed canonical under conflict must hard-fail")
	assert.Nil(t, cfg, "no Config returned on canonical-malformed conflict (MON-5371 contract)")
	assert.True(t, errors.Is(err, ErrRelocationConflict))
}

// Row 7: both, malformed-old.
func TestRelocate_MalformedOld_Conflict(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "[unclosed_array: yes\n")
	writeYAML(t, filepath.Join(new, configFileName), "credential_ref: newrelic-cli/default\n")

	got, err := detectRelocation(new)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRelocationConflict))
	assert.Equal(t, relocBothDivergent, got.Kind)
}

// Row 8: neither.
func TestRelocate_Neither_Defaults(t *testing.T) {
	_, new := setupRelocPair(t)
	got, err := detectRelocation(new)
	require.NoError(t, err)
	assert.Equal(t, relocNone, got.Kind)

	cfg, err := loadFromNewDir(new)
	require.NoError(t, err)
	assert.Equal(t, DefaultCredentialRef, cfg.CredentialRef)
}

// LoadForRuntime soft-degrade contract: under both-divergent with a readable
// canonical, returns canonical + nil error (after warning) — never silently
// swaps CredentialRef to default.
func TestLoadForRuntime_DivergentReadableCanonical_SoftDegrade(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "credential_ref: newrelic-cli/old\n")
	writeYAML(t, filepath.Join(new, configFileName), "credential_ref: newrelic-cli/canonical\n")
	// Reset the once gate so this test gets the warning side-effect deterministic
	reloConflictOnce = resetOnce()

	cfg, err := loadForRuntimeFromNewDir(new)
	require.NoError(t, err, "soft-degrade: readable canonical under conflict → warn + return canonical, no error")
	require.NotNil(t, cfg)
	assert.Equal(t, "newrelic-cli/canonical", cfg.CredentialRef, "must NOT swap to default")
}

// LoadForRuntime cfg!=nil contract: malformed canonical under conflict must
// hard-fail (no warn-and-default — that would mask corruption).
func TestLoadForRuntime_DivergentMalformedCanonical_HardFail(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "credential_ref: newrelic-cli/old\n")
	writeYAML(t, filepath.Join(new, configFileName), "[unclosed_array: yes\n")
	reloConflictOnce = resetOnce()

	cfg, err := loadForRuntimeFromNewDir(new)
	require.Error(t, err, "malformed canonical under conflict must hard-fail (MON-5371 contract)")
	assert.Nil(t, cfg)
}

// resetOnce returns a fresh sync.Once so warn-once side effects don't bleed
// between tests in this file.
func resetOnce() sync.Once { return sync.Once{} }

// HasUserConfig must register a relocOldOnly config as present — otherwise
// set-credential would falsely demand --ref on a box where the user has a
// pre-relocation config.yml under the old hand-rolled path. Mirrors row 2
// (TestRelocate_OldOnly_CopyNeeded) but for the §1.5.2 ref-defaulting path.
func TestHasUserConfig_RelocOldOnly_RegistersAsPresent(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "credential_ref: newrelic-cli/legacy\n")

	has, err := hasUserConfigInDir(new)
	require.NoError(t, err)
	assert.True(t, has, "old-only config.yml must register as present")
}

// And the negative case: neither side has a config.yml.
func TestHasUserConfig_RelocNeither_RegistersAsAbsent(t *testing.T) {
	_, new := setupRelocPair(t)
	has, err := hasUserConfigInDir(new)
	require.NoError(t, err)
	assert.False(t, has)
}

// HasUserConfig answers "does a config.yml file exist?" — not "is the state
// coherent?". When both canonical and old config.yml are present (the
// bothDivergent row that detectRelocation would flag as
// ErrRelocationConflict), the canonical readConfigYML check fires first and
// short-circuits before detectRelocation is reached. The conflict is
// surfaced through Load / LoadForRuntime at config-read time; not here.
// This test pins the short-circuit so a future refactor that reorders the
// probes doesn't accidentally route bothDivergent into the error path.
func TestHasUserConfig_BothPresent_CanonicalShortCircuits(t *testing.T) {
	old, new := setupRelocPair(t)
	writeYAML(t, filepath.Join(old, configFileName), "credential_ref: newrelic-cli/old\n")
	writeYAML(t, filepath.Join(new, configFileName), "credential_ref: newrelic-cli/new\n")

	has, err := hasUserConfigInDir(new)
	require.NoError(t, err)
	assert.True(t, has, "canonical readable → reported present without invoking detectRelocation")
}
