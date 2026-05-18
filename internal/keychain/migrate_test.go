package keychain

import (
	"errors"
	"os"
	"path/filepath"
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

// When the keyring already holds the (equal) secret but legacy originals
// still exist and will be scrubbed, that scrub IS a one-time migration side
// effect: planMigration must flag scrubbedOnly and record a change so the
// signal fires once (§1.8). No deleters → genuinely nothing to signal. #M2.
func TestPlanMigration_EqualButLegacyPresent_SignalsScrub(t *testing.T) {
	d := discovered{
		secrets:  []secretCandidate{{location: "file:/p#api_key", value: "NRAK-X"}},
		deleters: []labeledDeleter{{label: "file /p", del: func() error { return nil }}},
	}
	p, err := planMigration(svc, prof, ref, &config.Config{}, d, target("NRAK-X"), false)
	require.NoError(t, err)
	assert.False(t, p.writeSecret, "value already present — no write")
	assert.False(t, p.movedSecret)
	assert.True(t, p.scrubbedOnly, "scrubbing legacy originals is a one-time side effect")
	require.Len(t, p.changes, 1)
	assert.Equal(t, "api_key", p.changes[0].Field)
	assert.Contains(t, p.changes[0].To, "legacy copies removed")

	// No deleters present → truly nothing happened → no signal.
	p2, err := planMigration(svc, prof, ref, &config.Config{},
		discovered{secrets: []secretCandidate{{location: "file:/p#api_key", value: "NRAK-X"}}},
		target("NRAK-X"), false)
	require.NoError(t, err)
	assert.False(t, p2.scrubbedOnly)
	assert.Empty(t, p2.changes)
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

// --overwrite forcing a legacy value over a DIFFERENT existing keyring
// value is destructive — the plan flags replacedExisting so the command
// layer can warn. (Equal value or no target must NOT flag it.)
func TestPlanMigration_OverwriteReplacingDifferent_FlagsReplaced(t *testing.T) {
	d := discovered{secrets: []secretCandidate{{location: "file:/p#api_key", value: "NRAK-legacy"}}}

	p, err := planMigration(svc, prof, ref, &config.Config{}, d, target("NRAK-different"), true)
	require.NoError(t, err)
	assert.True(t, p.writeSecret)
	assert.True(t, p.replacedExisting, "overwrite of a differing existing value is destructive")

	// No pre-existing target → not a destructive replace.
	p2, err := planMigration(svc, prof, ref, &config.Config{}, d, noTarget, true)
	require.NoError(t, err)
	assert.False(t, p2.replacedExisting)
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

// discover() labels each legacy source so a scrub failure is actionable
// (names the specific source, not just the ref) — #11.
func TestDiscover_LabelsLegacyFileSource(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)
	t.Setenv(legacyKeychainScanDisabledEnv, "1") // hermetic: no security shell-out
	legacyDir := filepath.Join(tmp, "newrelic-cli")
	require.NoError(t, os.MkdirAll(legacyDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(legacyDir, "credentials"),
		[]byte("api_key=NRAK-x\n"), 0o600))
	d, err := discover()
	require.NoError(t, err)
	require.NotEmpty(t, d.deleters)
	var found bool
	for _, ld := range d.deleters {
		if strings.Contains(ld.label, "file ") && strings.Contains(ld.label, "credentials") {
			found = true
		}
	}
	assert.True(t, found, "legacy file deleter must carry a 'file <path>' label; got %+v", d.deleters)
}

// A backend that holds an empty api_key (external/legacy corruption — the
// adapter's own setter now rejects empty, but a pre-existing or
// out-of-band empty entry can still exist) must be reported distinctly as
// ErrCorruptedAPIKey, NOT folded into ErrMissingAPIKey (which would mask
// corruption and send the user down the wrong remediation path). #2.
func TestAPIKey_EmptyStored_DistinctFromMissing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "xdg"))
	t.Setenv("NEWRELIC_CLI_KEYRING_BACKEND", "file")
	t.Setenv("NEWRELIC_CLI_KEYRING_PASSPHRASE", "test-pass")
	t.Setenv(legacyKeychainScanDisabledEnv, "1")

	cfg := &config.Config{CredentialRef: "newrelic-cli/default"}
	st, err := openWith(cfg, false, false)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	// Plant an empty value via the underlying store, bypassing the
	// adapter's write-time empty guard (simulating backend/legacy
	// corruption).
	require.NoError(t, st.cs.Set(st.profile, KeyAPIKey, "", credstore.WithOverwrite()))

	_, err = st.APIKey()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCorruptedAPIKey), "empty stored value → ErrCorruptedAPIKey")
	assert.False(t, errors.Is(err, ErrMissingAPIKey), "must NOT look like never-set")
	assert.False(t, st.HasAPIKey(), "HasAPIKey must be false for an empty entry (so init can repair it)")
}

// The init/set-credential repair path (storeSecret) relies on this exact
// contract for a present-but-empty (corrupted) entry: the no-overwrite
// SetAPIKey fails ErrExists, APIKey() reports ErrCorruptedAPIKey (so the
// caller can tell "corrupt, safe to repair" from "real key, do not clobber"),
// and SetAPIKeyOverwrite then repairs it. If any link breaks, init silently
// fails to fix a corrupted keyring while `config show` says "not set". #7.
func TestRepairContract_EmptyEntry_OverwriteRepairs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "xdg"))
	t.Setenv("NEWRELIC_CLI_KEYRING_BACKEND", "file")
	t.Setenv("NEWRELIC_CLI_KEYRING_PASSPHRASE", "test-pass")
	t.Setenv(legacyKeychainScanDisabledEnv, "1")

	cfg := &config.Config{CredentialRef: "newrelic-cli/default"}
	st, err := openWith(cfg, false, false)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()

	// Plant an empty (corrupt) entry, bypassing the write-time guard.
	require.NoError(t, st.cs.Set(st.profile, KeyAPIKey, "", credstore.WithOverwrite()))

	require.False(t, st.HasAPIKey(), "empty entry must not look usable")

	err = st.SetAPIKey("NRAK-repaired-value-x")
	require.Error(t, err, "no-overwrite write over a physical entry must fail")
	assert.True(t, errors.Is(err, credstore.ErrExists))

	_, apErr := st.APIKey()
	assert.True(t, errors.Is(apErr, ErrCorruptedAPIKey),
		"caller distinguishes corrupt (repairable) from a real key (clobber)")

	require.NoError(t, st.SetAPIKeyOverwrite("NRAK-repaired-value-x"))
	got, err := st.APIKey()
	require.NoError(t, err)
	assert.Equal(t, "NRAK-repaired-value-x", got, "repair must leave a usable key")
}

func TestConflictErr_NoValueLeak(t *testing.T) {
	err := secretConflictErr(svc, prof, ref, []secretCandidate{
		{location: "file:/p#api_key", value: "SUPER-SECRET"},
	}, true)
	assert.True(t, errors.Is(err, credstore.ErrMigrationConflict))
	assert.False(t, strings.Contains(err.Error(), "SUPER-SECRET"))
	assert.Contains(t, err.Error(), "keyring:newrelic-cli/default/api_key")
}
