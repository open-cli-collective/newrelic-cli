package keychain

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
)

const (
	svc  = "newrelic-cli"
	prof = "default"
	ref  = "newrelic-cli/default"
)

func noTarget() (string, bool) { return "", false }
func target(v string) func() (string, bool) {
	return func() (string, bool) { return v, true }
}

// --- secret (api_key): fail loud on divergence, never precedence-pick ------

func TestPlanMigration_SingleSecretSource_Writes(t *testing.T) {
	d := discovered{secrets: []secretCandidate{{location: "file:/p#api_key", value: "NRAK-1"}}}
	p, err := planMigration(svc, prof, ref, &config.Config{}, d, noTarget, false)
	require.NoError(t, err)
	assert.True(t, p.writeSecret)
	assert.Equal(t, "NRAK-1", p.secretValue)
	assert.True(t, p.movedSecret)
	require.Len(t, p.changes, 1)
	assert.Equal(t, "api_key", p.changes[0].Field)
	assert.Equal(t, "keyring:newrelic-cli/default/api_key", p.changes[0].To)
}

func TestPlanMigration_EqualMultiSource_Idempotent(t *testing.T) {
	// keychain + file agree, and the keyring already holds the same value:
	// no write, no signal — just cleanup of leftover originals.
	d := discovered{secrets: []secretCandidate{
		{location: "keychain:newrelic-cli/api_key", value: "NRAK-X"},
		{location: "file:/p#api_key", value: "NRAK-X"},
	}}
	p, err := planMigration(svc, prof, ref, &config.Config{}, d, target("NRAK-X"), false)
	require.NoError(t, err)
	assert.False(t, p.writeSecret)
	assert.False(t, p.movedSecret)
	assert.Empty(t, p.changes)
}

func TestPlanMigration_SecretDivergence_KeychainVsFile_FailsNamingAll(t *testing.T) {
	d := discovered{secrets: []secretCandidate{
		{location: "keychain:newrelic-cli/api_key", value: "NRAK-A"},
		{location: "file:/p#api_key", value: "NRAK-B"},
	}}
	_, err := planMigration(svc, prof, ref, &config.Config{}, d, noTarget, false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, credstore.ErrMigrationConflict))
	msg := err.Error()
	assert.Contains(t, msg, "keychain:newrelic-cli/api_key")
	assert.Contains(t, msg, "file:/p#api_key")
	// §1.12: never the value, masked or not.
	assert.NotContains(t, msg, "NRAK-A")
	assert.NotContains(t, msg, "NRAK-B")
}

func TestPlanMigration_SecretLegacyVsKeyring_FailsUnlessOverwrite(t *testing.T) {
	d := discovered{secrets: []secretCandidate{{location: "file:/p#api_key", value: "NRAK-legacy"}}}

	_, err := planMigration(svc, prof, ref, &config.Config{}, d, target("NRAK-keyring"), false)
	require.Error(t, err)
	assert.True(t, errors.Is(err, credstore.ErrMigrationConflict))
	assert.NotContains(t, err.Error(), "NRAK-legacy")
	assert.NotContains(t, err.Error(), "NRAK-keyring")

	// --overwrite forces the legacy value over the existing keyring entry.
	p, err := planMigration(svc, prof, ref, &config.Config{}, d, target("NRAK-keyring"), true)
	require.NoError(t, err)
	assert.True(t, p.writeSecret)
	assert.Equal(t, "NRAK-legacy", p.secretValue)
}

func TestPlanMigration_LegacyVsLegacyDisagree_OverwriteStillFails(t *testing.T) {
	d := discovered{secrets: []secretCandidate{
		{location: "keychain:newrelic-cli/api_key", value: "NRAK-A"},
		{location: "file:/p#api_key", value: "NRAK-B"},
	}}
	_, err := planMigration(svc, prof, ref, &config.Config{}, d, noTarget, true)
	require.Error(t, err, "--overwrite cannot pick among divergent legacy sources")
	assert.True(t, errors.Is(err, credstore.ErrMigrationConflict))
}

func TestPlanMigration_NothingLegacy_NoOp(t *testing.T) {
	p, err := planMigration(svc, prof, ref, &config.Config{}, discovered{}, noTarget, false)
	require.NoError(t, err)
	assert.False(t, p.writeSecret)
	assert.Empty(t, p.changes)
}

// --- non-secret (account_id/region): precedence resolves, never a conflict,
// exhaustive divergent pairs ------------------------------------------------

func nsFold(t *testing.T, cfg *config.Config, d discovered) migrationPlan {
	t.Helper()
	p, err := planMigration(svc, prof, ref, cfg, d, noTarget, false)
	require.NoError(t, err)
	return p
}

func TestPlanMigration_NonSecret_ConfigPresentWinsOverKeychain(t *testing.T) {
	cfg := &config.Config{AccountID: "EXISTING"}
	d := discovered{nonSecrets: []nonSecretCandidate{
		{field: "account_id", value: "FROM-KEYCHAIN", priority: 0, location: "keychain:newrelic-cli/account_id"},
	}}
	p := nsFold(t, cfg, d)
	assert.Empty(t, p.foldAccountID, "config.yml value already set must win — no fold")
	assert.NotContains(t, p.movedNonSecret, "account_id")
}

func TestPlanMigration_NonSecret_ConfigPresentWinsOverFile(t *testing.T) {
	cfg := &config.Config{Region: "EU"}
	d := discovered{nonSecrets: []nonSecretCandidate{
		{field: "region", value: "US", priority: 1, location: "file:/p#region"},
	}}
	p := nsFold(t, cfg, d)
	assert.Empty(t, p.foldRegion)
	assert.NotContains(t, p.movedNonSecret, "region")
}

func TestPlanMigration_NonSecret_KeychainBeatsFileWhenConfigAbsent(t *testing.T) {
	d := discovered{nonSecrets: []nonSecretCandidate{
		{field: "account_id", value: "KC", priority: 0, location: "keychain:newrelic-cli/account_id"},
		{field: "account_id", value: "FILE", priority: 1, location: "file:/p#account_id"},
	}}
	p := nsFold(t, &config.Config{}, d)
	assert.Equal(t, "KC", p.foldAccountID)
	assert.Contains(t, p.movedNonSecret, "account_id")
	// Recorded in _migration with a config destination (§1.8: non-secret
	// moves are signaled too).
	var found bool
	for _, c := range p.changes {
		if c.Field == "account_id" {
			found = true
			assert.Contains(t, c.To, "config:")
			assert.Contains(t, c.To, "#account_id")
		}
	}
	assert.True(t, found, "account_id move must be recorded in _migration")
}

func TestPlanMigration_NonSecret_FileOnlyAndKeychainOnly(t *testing.T) {
	pFile := nsFold(t, &config.Config{}, discovered{nonSecrets: []nonSecretCandidate{
		{field: "region", value: "EU", priority: 1, location: "file:/p#region"},
	}})
	assert.Equal(t, "EU", pFile.foldRegion)

	pKC := nsFold(t, &config.Config{}, discovered{nonSecrets: []nonSecretCandidate{
		{field: "account_id", value: "999", priority: 0, location: "keychain:newrelic-cli/account_id"},
	}})
	assert.Equal(t, "999", pKC.foldAccountID)
}

func TestPlanMigration_NonSecret_NeverConflicts(t *testing.T) {
	// Divergent non-secret across keychain and file is resolved by
	// precedence, NEVER an error (only the secret fails loud).
	d := discovered{nonSecrets: []nonSecretCandidate{
		{field: "region", value: "US", priority: 0, location: "keychain:newrelic-cli/region"},
		{field: "region", value: "EU", priority: 1, location: "file:/p#region"},
	}}
	p, err := planMigration(svc, prof, ref, &config.Config{}, d, noTarget, false)
	require.NoError(t, err)
	assert.Equal(t, "US", p.foldRegion) // keychain (priority 0) wins
}

func TestConflictErr_NoValueLeak(t *testing.T) {
	err := secretConflictErr(svc, prof, ref, []secretCandidate{
		{location: "file:/p#api_key", value: "SUPER-SECRET"},
	}, true)
	assert.True(t, errors.Is(err, credstore.ErrMigrationConflict))
	assert.False(t, strings.Contains(err.Error(), "SUPER-SECRET"))
	assert.Contains(t, err.Error(), "keyring:newrelic-cli/default/api_key")
}
