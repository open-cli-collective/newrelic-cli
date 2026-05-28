package keychain

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/config"
)

// One-time legacy migration (§1.8 / §2.5). nrq's legacy sources hold THREE
// fields but only `api_key` is a secret: it moves to the credstore keyring
// (fail-loud on divergence — never precedence-pick a secret); the non-secret
// `account_id`/`region` are folded into config.yml (precedence MAY resolve a
// non-secret divergence). The stderr signal is emitted only AFTER the full
// success boundary — keyring write, config save, AND legacy scrub all
// succeed — so a "one-time operation" line is never printed while a plaintext
// copy still exists. Idempotent: once the originals are gone there is nothing
// to do and no signal fires.

// legacyKeychainService is the only macOS Keychain service nrq has used
// historically (it never renamed, unlike slck). Accounts: api_key (secret),
// account_id, region (non-secret).
const legacyKeychainService = "newrelic-cli"

// secretField is the legacy field/account name of the access secret.
const secretField = "api_key"

// nonSecretFields are the legacy field/account names that are non-secret
// config (folded into config.yml, not the keyring).
var nonSecretFields = []string{"account_id", "region"}

// legacyKeychainScanDisabledEnv is a test-only seam: when set, discover()
// skips the darwin `security` shell-out so the suite is hermetic and never
// touches the real login Keychain. Production never sets it — legacy Keychain
// discovery must run regardless of the destination backend (§2.5: a macOS
// user who opts into keyring.backend:file must still have old Keychain items
// migrated).
const legacyKeychainScanDisabledEnv = "NRQ_TEST_DISABLE_LEGACY_KEYCHAIN_SCAN"

// secretCandidate is one discovered legacy `api_key` value.
type secretCandidate struct {
	location string // non-secret descriptor (never the value)
	value    string
}

// nonSecretCandidate is one discovered legacy non-secret value.
type nonSecretCandidate struct {
	field    string // account_id | region
	value    string
	priority int    // lower wins: keychain(0) beats file(1)
	location string // human-readable source descriptor (file:/p#field, keychain:svc/acct)
}

// labeledDeleter removes one legacy original; label names the source (e.g.
// "macOS Keychain newrelic-cli/api_key", "file <path>") so a scrub failure
// is actionable rather than only naming the ref.
type labeledDeleter struct {
	label string
	del   func() error
}

// discovered is everything found on disk/keychain plus the deleters that
// remove every legacy original after a successful migration.
type discovered struct {
	secrets    []secretCandidate
	nonSecrets []nonSecretCandidate
	deleters   []labeledDeleter // every legacy original that currently exists
}

// migrateLegacyOverwrite runs the one-time migration. overwrite (the §1.8
// `--overwrite` path) forces a legacy api_key over an existing keyring entry;
// it cannot resolve a legacy-vs-legacy disagreement — the user must pick.
func migrateLegacyOverwrite(s *Store, cfg *config.Config, overwrite bool) error {
	d, err := discover()
	if err != nil {
		// A legacy source could not be read definitively (locked/denied/
		// timed-out Keychain). Fail loud (§1.8): never migrate on a partial
		// view that could miss a divergence or strand the original.
		return err
	}
	if len(d.secrets) == 0 && len(d.nonSecrets) == 0 {
		return nil // nothing legacy anywhere — the steady state
	}

	plan, err := planMigration(s.service, s.profile, s.ref, cfg, d,
		func() (string, bool) { return currentAPIKey(s) }, overwrite)
	if err != nil {
		return err
	}

	// Phase 1: write the secret bundle (overwrite only when forced).
	if plan.writeSecret {
		var opts []credstore.SetOpt
		if overwrite {
			opts = append(opts, credstore.WithOverwrite())
		}
		if _, err := s.cs.SetBundle(s.profile,
			map[string]string{KeyAPIKey: plan.secretValue}, opts...); err != nil {
			return fmt.Errorf("migrate to keyring %s: %w", s.ref, err)
		}
	}

	// Phase 2: fold non-secret values into config.yml and persist it (this
	// also writes credential_ref, so the migration is not re-attempted).
	if plan.foldAccountID != "" {
		cfg.AccountID = plan.foldAccountID
	}
	if plan.foldRegion != "" {
		cfg.Region = plan.foldRegion
	}
	if err := cfg.Save(); err != nil {
		// Only claim a keyring write if one actually happened this run
		// (an idempotent re-run has plan.writeSecret == false).
		if plan.writeSecret {
			return fmt.Errorf("migration wrote the keyring but saving config.yml failed: %w", err)
		}
		return fmt.Errorf("migration could not save config.yml at %s: %w", s.ref, err)
	}

	// Phase 3: delete every legacy original. If ANY deleter fails the
	// migration is incomplete — return the error (naming the specific
	// source) and emit NO signal (nothing may claim "one-time operation"
	// with a legacy copy still on disk). Retry is idempotent: the keyring
	// already holds the (equal) value, so the next run is a no-op write
	// and re-attempts the remaining deleters.
	for _, ld := range d.deleters {
		if err := ld.del(); err != nil {
			return fmt.Errorf("migration wrote the keyring/config but could not remove legacy original [%s] (%s): %w",
				ld.label, s.ref, err)
		}
	}

	// Phase 4: full success boundary crossed.
	//
	// --overwrite that replaced a DIFFERENT existing keyring value is
	// destructive — surface it now (NOT before Phase 3, so the warning is
	// never printed for a migration that then failed to complete; never
	// the value, §1.12).
	if plan.replacedExisting {
		fmt.Fprintf(os.Stderr,
			"warning: --overwrite replaced an existing, different api_key in keyring %s\n", s.ref)
	}

	// Surface the stderr signal for every field actually moved this run
	// (§1.8 bans silent migration; §2.5 moves all three).
	if plan.movedSecret || plan.scrubbedOnly || len(plan.movedNonSecret) > 0 {
		if plan.movedSecret {
			credstore.EmitMigrationStderr(secretField, s.ref)
		} else if plan.scrubbedOnly {
			fmt.Fprintf(os.Stderr,
				"removed legacy %s credential source(s) for %s "+
					"(the keyring already held it); this is a one-time operation\n",
				secretField, s.ref)
		}
		cfgPath, perr := config.Path()
		if perr != nil {
			return perr
		}
		for _, f := range plan.movedNonSecret {
			// Distinct human line: non-secret moves go to config.yml,
			// NOT the keyring — do not reuse the keyring wording.
			fmt.Fprintf(os.Stderr,
				"migrated %s to config %s; this is a one-time operation\n",
				f, cfgPath)
		}
	}
	return nil
}

// migrationPlan is the pure result of resolving discovered candidates.
type migrationPlan struct {
	writeSecret    bool
	secretValue    string
	foldAccountID  string // "" = leave cfg.AccountID as-is
	foldRegion     string
	movedSecret    bool
	movedNonSecret []string // fields whose value changed config.yml this run
	// replacedExisting: --overwrite forced a legacy value over a DIFFERENT
	// pre-existing keyring value (destructive — warn the user).
	replacedExisting bool
	// scrubbedOnly: the keyring already held the (equal) secret so nothing
	// was written, but legacy originals existed and are being deleted. That
	// removal is itself a one-time migration side effect and must be
	// signaled once (§1.8 — a silent scrub of the user's plaintext file or
	// legacy Keychain item is still a migration the user should learn of).
	scrubbedOnly bool
}

// planMigration is the pure §1.8 resolver. It performs NO I/O (`current`
// injects the existing keyring api_key lookup) so every branch — secret
// legacy-vs-legacy disagreement, legacy-vs-keyring, idempotent equal,
// overwrite, non-secret precedence fold — is unit-testable with synthetic
// candidates. ALL secret conflicts are detected before any mutation is
// proposed.
func planMigration(service, profile, ref string, cfg *config.Config, d discovered,
	current func() (string, bool), overwrite bool) (migrationPlan, error) {

	var p migrationPlan

	// --- secret: api_key (fail loud on divergence; never precedence-pick) ---
	if len(d.secrets) > 0 {
		distinct := map[string]bool{}
		for _, c := range d.secrets {
			distinct[c.value] = true
		}
		target, hasTarget := current()
		switch {
		case len(distinct) > 1:
			// Legacy sources disagree among themselves: --overwrite cannot
			// pick a winner here either (§1.8 — the user must).
			return migrationPlan{}, secretConflictErr(service, profile, ref, d.secrets, hasTarget)
		case hasTarget && !overwrite && secretDisagrees(distinct, target):
			return migrationPlan{}, secretConflictErr(service, profile, ref, d.secrets, hasTarget)
		case hasTarget && !secretDisagrees(distinct, target):
			// Already migrated (values match): no write. But if legacy
			// originals still exist they are about to be scrubbed by the
			// deleters — that IS a one-time migration side effect, so
			// signal once (§1.8).
			if len(d.deleters) > 0 {
				p.scrubbedOnly = true
			}
		default:
			p.writeSecret = true
			p.secretValue = d.secrets[0].value
			p.movedSecret = true
			// Reached with a pre-existing target only when overwrite is set
			// AND the value differs (the no-overwrite-disagree and
			// agree cases are handled above) — i.e. a destructive replace.
			p.replacedExisting = hasTarget && overwrite && secretDisagrees(distinct, target)
		}
	}

	// --- non-secret: account_id / region (precedence resolves; never a
	// conflict). Precedence: an existing config.yml value wins (a re-run must
	// not revert a value the user already set — mirrors the MON-5328
	// store-wins fix); among legacy sources keychain beats file. ---
	folds := map[string]*nonSecretCandidate{}
	for i := range d.nonSecrets {
		c := &d.nonSecrets[i]
		cur, ok := folds[c.field]
		if !ok || c.priority < cur.priority {
			folds[c.field] = c
		}
	}
	for _, field := range nonSecretFields {
		c := folds[field]
		if c == nil {
			continue
		}
		existing := configFieldValue(cfg, field)
		if existing != "" {
			// config.yml already has it: highest precedence, no move.
			continue
		}
		switch field {
		case "account_id":
			p.foldAccountID = c.value
		case "region":
			p.foldRegion = c.value
		}
		p.movedNonSecret = append(p.movedNonSecret, field)
	}
	sort.Strings(p.movedNonSecret)
	return p, nil
}

func configFieldValue(cfg *config.Config, field string) string {
	switch field {
	case "account_id":
		return cfg.AccountID
	case "region":
		return cfg.Region
	}
	return ""
}

// currentAPIKey reports the existing credstore api_key (post-Open).
func currentAPIKey(s *Store) (string, bool) {
	v, err := s.cs.Get(s.profile, KeyAPIKey)
	if err != nil || v == "" {
		return "", false
	}
	return v, true
}

func secretDisagrees(distinct map[string]bool, target string) bool {
	for v := range distinct {
		if v != target {
			return true
		}
	}
	return false
}

// secretConflictErr builds the §1.8 error: names every legacy source and the
// keyring target, never a value (masked or not). Pure — no *Store.
func secretConflictErr(service, profile, ref string, group []secretCandidate, hasTarget bool) error {
	locs := make([]string, 0, len(group)+1)
	for _, c := range group {
		locs = append(locs, c.location)
	}
	if hasTarget {
		locs = append(locs, fmt.Sprintf("keyring:%s/%s/%s", service, profile, KeyAPIKey))
	}
	return credstore.MigrationConflictError("nrq", secretField, strings.Join(locs, ", "), ref)
}

// discover enumerates every legacy source that currently exists, independent
// of the destination backend (§2.5). macOS Keychain reads are migration-only
// and darwin-only (the sole sanctioned `security` shell-out). The plaintext
// file path is the released layout — $XDG_CONFIG_HOME/newrelic-cli/credentials
// else ~/.config/newrelic-cli/credentials — on Linux AND Windows alike (the
// legacy code has no %APPDATA% branch, so no speculative Windows path).
func discover() (discovered, error) {
	var d discovered

	if runtime.GOOS == "darwin" && os.Getenv(legacyKeychainScanDisabledEnv) == "" {
		var kcAccounts []string
		v, ok, err := keychainRead(legacyKeychainService, secretField)
		if err != nil {
			return discovered{}, err
		}
		if ok {
			d.secrets = append(d.secrets, secretCandidate{
				location: fmt.Sprintf("keychain:%s/%s", legacyKeychainService, secretField),
				value:    v,
			})
			kcAccounts = append(kcAccounts, secretField)
		}
		for _, field := range nonSecretFields {
			v, ok, err := keychainRead(legacyKeychainService, field)
			if err != nil {
				return discovered{}, err
			}
			if ok {
				d.nonSecrets = append(d.nonSecrets, nonSecretCandidate{
					field:    field,
					value:    v,
					priority: 0, // keychain beats file
					location: fmt.Sprintf("keychain:%s/%s", legacyKeychainService, field),
				})
				kcAccounts = append(kcAccounts, field)
			}
		}
		if len(kcAccounts) > 0 {
			accounts := kcAccounts // capture
			d.deleters = append(d.deleters, labeledDeleter{
				label: fmt.Sprintf("macOS Keychain service %s (%s)",
					legacyKeychainService, strings.Join(accounts, ", ")),
				del: func() error {
					// Best effort across every account so a transient
					// denial on one does not strand the others; report
					// the complete failure set (still returns non-nil so
					// the outer Phase-3 abort + no-signal invariant holds).
					var errs []error
					for _, a := range accounts {
						if err := keychainDelete(legacyKeychainService, a); err != nil {
							errs = append(errs, fmt.Errorf("%s/%s: %w", legacyKeychainService, a, err))
						}
					}
					return errors.Join(errs...)
				},
			})
		}
	}

	// Plaintext credentials file: enumerate BOTH the old hand-rolled location
	// AND the new canonical (post-MON-5373) location, path-identity deduped.
	// The file lives in the same dir as config.yml, so the resolver switch
	// relocates it on macOS/Windows — without dual-probe a workstation
	// upgraded across the port would silently retain a plaintext secret in
	// the old dir. The resolver is a package var so unit tests can exercise
	// the dual-path matrix on Linux CI (where statedir collapses old≡new).
	paths, err := credentialFileCandidates()
	if err != nil {
		return discovered{}, err
	}
	type pathVals struct {
		path string
		vals map[string]string
	}
	var present []pathVals
	for _, p := range paths {
		v := readLegacyFile(p)
		if len(v) > 0 {
			present = append(present, pathVals{path: p, vals: v})
		}
	}

	// Conflict semantics on the parsed/effective projection (api_key /
	// account_id / region). Byte-equal would false-conflict on harmless
	// ordering or trailing-newline differences (Codex r2 catch).
	if len(present) > 1 {
		fields := append([]string{secretField}, nonSecretFields...)
		for _, f := range fields {
			a, ok1 := present[0].vals[f]
			b, ok2 := present[1].vals[f]
			if ok1 && ok2 && a != b {
				return discovered{}, fmt.Errorf(
					"legacy credentials diverge between %s and %s on field %q; reconcile (delete one) before re-running",
					present[0].path, present[1].path, f)
			}
		}
	}

	// Per-path enumeration: each path contributes its own location string and
	// its own deleter. On Linux the dedup above collapses to one path; on
	// macOS/Windows BOTH paths are reported and BOTH are scrubbed on success.
	for _, pv := range present {
		path := pv.path
		fileVals := pv.vals
		fileDeleter := func() error {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		usedFile := false
		if v, ok := fileVals[secretField]; ok && v != "" {
			d.secrets = append(d.secrets, secretCandidate{
				location: fmt.Sprintf("file:%s#%s", path, secretField),
				value:    v,
			})
			usedFile = true
		}
		for _, field := range nonSecretFields {
			if v, ok := fileVals[field]; ok && v != "" {
				d.nonSecrets = append(d.nonSecrets, nonSecretCandidate{
					field:    field,
					value:    v,
					priority: 1, // file loses to keychain
					location: fmt.Sprintf("file:%s#%s", path, field),
				})
				usedFile = true
			}
		}
		if usedFile {
			d.deleters = append(d.deleters, labeledDeleter{
				label: "file " + path,
				del:   fileDeleter,
			})
		}
	}
	return d, nil
}

// ScrubLegacyKeychain best-effort deletes nrq's legacy macOS Keychain
// accounts (service "newrelic-cli": api_key/account_id/region). It is a
// no-op on non-darwin and when the test seam disables the scan. `config
// clear --all` calls it so a pre-migration wipe is not silently undone by
// the next Open() re-migrating a surviving legacy Keychain item — the same
// restore-on-next-Open() gap the plaintext-file scrub closes. keychainDelete
// already maps errSecItemNotFound to nil, so an absent account is success;
// every account is attempted and the full failure set is returned.
func ScrubLegacyKeychain() error {
	if runtime.GOOS != "darwin" || os.Getenv(legacyKeychainScanDisabledEnv) != "" {
		return nil
	}
	var errs []error
	for _, a := range append([]string{secretField}, nonSecretFields...) {
		if err := keychainDelete(legacyKeychainService, a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// credentialFileCandidates is the package-level seam for credentials-file
// discovery. Production routes through config.CredentialFileCandidates;
// tests can override to exercise the §1.8 dual-probe matrix on Linux CI
// where statedir's resolver collapses old≡new (Codex PR-r1 portability fix).
var credentialFileCandidates = config.CredentialFileCandidates

// readLegacyFile parses the legacy flat key=value credentials file (NOT an
// INI; no [sections]). Missing file → nil (the steady state, not an error).
func readLegacyFile(path string) map[string]string {
	f, err := os.Open(path) //nolint:gosec // migration reading nrq's own legacy file
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '='); i > 0 {
			m[line[:i]] = line[i+1:]
		}
	}
	return m
}

// securityTimeout bounds each `security` shell-out: a hung subprocess (a
// Keychain unlock prompt, SIP/MDM stall) must fail the one-time migration
// with a clear error rather than block the CLI's first run indefinitely.
const securityTimeout = 5 * time.Second

// securityErrItemNotFound is `security`'s exit status when the item is absent
// (errSecItemNotFound). Only this is idempotent success — a denial/locked
// failure must surface so we don't leave a legacy secret behind.
const securityErrItemNotFound = 44

// securityRun executes `security` with args under securityTimeout and
// classifies the outcome: exitCode 0 on success or the clean non-zero exit
// code; timedOut=true if the deadline fired; err only for a non-exit failure
// (binary missing, etc.). It is a package var so tests can drive the
// not-found / denied / timeout classification in keychainRead and
// ScrubLegacyKeychain without shelling out (the highest-risk §1.8 paths).
var securityRun = func(args ...string) (out []byte, exitCode int, timedOut bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), securityTimeout)
	defer cancel()
	o, e := exec.CommandContext(ctx, "security", args...).Output() //nolint:gosec // darwin-only migration on nrq's own legacy items
	if ctx.Err() != nil {
		return nil, -1, true, nil
	}
	if e != nil {
		var ee *exec.ExitError
		if errors.As(e, &ee) {
			return nil, ee.ExitCode(), false, nil
		}
		return nil, -1, false, e
	}
	return o, 0, false, nil
}

// keychainRead is tri-state: (value, true, nil) when present; ("", false,
// nil) ONLY when `security` definitively reports the item absent
// (errSecItemNotFound) or it is present-but-empty; ("", false, err) for any
// other failure — timeout, locked Keychain, access denial, SIP/MDM. A
// non-not-found failure must NOT be folded into "absent": that would let
// §1.8 silently skip a real legacy secret, miss a divergence with the file
// or keyring, and leave the original behind.
func keychainRead(service, account string) (string, bool, error) {
	out, code, timedOut, err := securityRun("find-generic-password", "-s", service, "-a", account, "-w")
	if timedOut {
		return "", false, fmt.Errorf(
			"read legacy keychain item %s/%s timed out after %s (locked Keychain or unlock prompt?)",
			service, account, securityTimeout)
	}
	if err != nil {
		return "", false, fmt.Errorf("read legacy keychain item %s/%s: %w", service, account, err)
	}
	if code == securityErrItemNotFound {
		return "", false, nil // definitively absent — not an error
	}
	if code != 0 {
		return "", false, fmt.Errorf(
			"read legacy keychain item %s/%s: security exited %d (access denied or locked Keychain?)",
			service, account, code)
	}
	v := strings.TrimRight(string(out), "\r\n")
	if v == "" {
		return "", false, nil // present-but-empty: nothing to migrate
	}
	return v, true, nil
}

func keychainDelete(service, account string) error {
	_, code, timedOut, err := securityRun("delete-generic-password", "-s", service, "-a", account)
	if timedOut {
		return fmt.Errorf("remove legacy keychain item %s/%s timed out after %s", service, account, securityTimeout)
	}
	if err != nil {
		return fmt.Errorf("remove legacy keychain item %s/%s: %w", service, account, err)
	}
	if code == 0 || code == securityErrItemNotFound {
		return nil // removed, or already absent — idempotent cleanup
	}
	return fmt.Errorf("remove legacy keychain item %s/%s: security exited %d", service, account, code)
}
