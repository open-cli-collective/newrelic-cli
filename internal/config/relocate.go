package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

// ErrRelocationConflict is returned by Load (and surfaced through
// LoadForRuntime) when both the old hand-rolled config dir and the new
// statedir-resolved config dir contain a config.yml whose default-applied
// content differs. Mutation-free: nothing is copied, nothing is overwritten.
// The user reconciles by running `nrq init` (which aborts at its pre-write
// gate) or by deleting one side.
var ErrRelocationConflict = errors.New("config: shared old/new config diverge")

// relocKind is the four-way classification used by the relocation detector.
// Linux always collapses to relocNone because old and new paths are identical
// (statedir on Linux ≡ $XDG_CONFIG_HOME else $HOME/.config).
type relocKind int

const (
	relocNone          relocKind = iota // old absent OR old==new (Linux short-circuit)
	relocOldOnly                        // only the old hand-rolled config.yml exists
	relocBothEqual                      // both exist with materially-equal Configs
	relocBothDivergent                  // both exist with materially-different Configs (or malformed)
)

// SharedRelocation is the result of DetectConfigRelocation.
type SharedRelocation struct {
	Kind       relocKind
	OldPath    string // old hand-rolled config dir; "" on no-HOME edge
	NewPath    string // statedir-resolved config dir
	CopyNeeded bool   // relocOldOnly only
}

// oldHandRolledConfigDir reproduces the pre-MON-5373 resolver:
// $XDG_CONFIG_HOME if set, else $HOME/.config; then "/newrelic-cli". Same
// shape across OSes (the released layout had no %APPDATA% branch). A missing
// HOME is an error (matches the original).
func oldHandRolledConfigDir() (string, error) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, appDirName), nil
}

// OldConfigPath returns the pre-MON-5373 hand-rolled config.yml location.
// Exported so `nrq config clear --all` can scrub it alongside the new path
// (an old file would otherwise silently resurrect config post-clear on the
// next runtime-fallback Load).
func OldConfigPath() (string, error) {
	dir, err := oldHandRolledConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFileName), nil
}

// OldHandRolledCredentialsPath returns the pre-MON-5373 location of the
// plaintext credentials file ($XDG_CONFIG_HOME/$HOME/.config/newrelic-cli/
// credentials). The §1.8 keychain migrator scans this AND the new-canonical
// location (see CredentialFileCandidates in config.go).
func OldHandRolledCredentialsPath() (string, error) {
	dir, err := oldHandRolledConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, credFileName), nil
}

// DetectConfigRelocation classifies the old/new pair without touching disk
// beyond stats and reads. Never copies, never writes. On Linux (old==new) it
// short-circuits to relocNone.
func DetectConfigRelocation() (SharedRelocation, error) {
	newDir, err := Dir()
	if err != nil {
		return SharedRelocation{}, err
	}
	return detectRelocation(newDir)
}

// detectRelocation is the testable core: the new-dir path is injected so
// macOS/Windows divergence can be exercised on Linux CI.
func detectRelocation(newDir string) (SharedRelocation, error) {
	oldDir, err := oldHandRolledConfigDir()
	if err != nil {
		// Old path unresolvable (no HOME): treat as relocNone with new-only.
		// Load still works against new; the gate is harmless.
		return SharedRelocation{Kind: relocNone, NewPath: newDir}, nil
	}
	if oldDir == newDir {
		// Linux: identical paths — nothing to relocate.
		return SharedRelocation{Kind: relocNone, OldPath: oldDir, NewPath: newDir}, nil
	}

	oldYML := filepath.Join(oldDir, configFileName)
	newYML := filepath.Join(newDir, configFileName)
	oldPresent := fileExists(oldYML)
	newPresent := fileExists(newYML)
	switch {
	case !oldPresent && !newPresent:
		return SharedRelocation{Kind: relocNone, OldPath: oldDir, NewPath: newDir}, nil
	case oldPresent && !newPresent:
		// Validate old parses cleanly BEFORE signaling CopyNeeded — otherwise
		// init's ApplyConfigRelocation would propagate a malformed legacy
		// file into the new dir and Load would die parsing it post-copy.
		// §3.2 malformed-old: fail loud, mutate nothing. (MON-5371 lesson.)
		if _, _, oerr := readConfigYML(oldYML); oerr != nil {
			return SharedRelocation{Kind: relocBothDivergent, OldPath: oldDir, NewPath: newDir},
				fmt.Errorf("%w: old %s is malformed: %w", ErrRelocationConflict, oldYML, oerr)
		}
		return SharedRelocation{Kind: relocOldOnly, OldPath: oldDir, NewPath: newDir, CopyNeeded: true}, nil
	case !oldPresent && newPresent:
		return SharedRelocation{Kind: relocNone, OldPath: oldDir, NewPath: newDir}, nil
	}

	// Both present — load and compare comparable subset.
	oldCfg, _, oerr := readConfigYML(oldYML)
	newCfg, _, nerr := readConfigYML(newYML)
	if oerr != nil {
		return SharedRelocation{Kind: relocBothDivergent, OldPath: oldDir, NewPath: newDir},
			fmt.Errorf("%w: old %s unreadable: %w", ErrRelocationConflict, oldYML, oerr)
	}
	if nerr != nil {
		return SharedRelocation{Kind: relocBothDivergent, OldPath: oldDir, NewPath: newDir},
			fmt.Errorf("%w: new %s unreadable: %w", ErrRelocationConflict, newYML, nerr)
	}
	if configsMaterialEqual(oldCfg, newCfg) {
		return SharedRelocation{Kind: relocBothEqual, OldPath: oldDir, NewPath: newDir}, nil
	}
	return SharedRelocation{Kind: relocBothDivergent, OldPath: oldDir, NewPath: newDir},
		fmt.Errorf("%w: old %s and new %s have different settings; reconcile (or delete one) before running nrq init",
			ErrRelocationConflict, oldYML, newYML)
}

// configsMaterialEqual compares two Configs after applying defaults on both
// sides (so an omitted credential_ref — semantically DefaultCredentialRef —
// compares equal to an explicit DefaultCredentialRef). reflect.DeepEqual on
// the whole default-applied struct: future Config fields are automatic
// divergence-triggers, no maintenance burden.
func configsMaterialEqual(a, b Config) bool {
	a.applyDefaults()
	b.applyDefaults()
	return reflect.DeepEqual(a, b)
}

// ApplyConfigRelocation copies the single config.yml file from old → new
// atomically; idempotent (skips if new already exists). The old dir is NOT
// modified — leave-old gives the user a recovery point and matches the
// MON-5370/5371/5372 family invariant. Called only from `nrq init`'s
// pre-write gate.
func ApplyConfigRelocation(r SharedRelocation) error {
	if !r.CopyNeeded {
		return nil
	}
	if r.OldPath == "" || r.NewPath == "" {
		return fmt.Errorf("config: ApplyConfigRelocation called with empty path")
	}
	if err := os.MkdirAll(r.NewPath, DirPerm); err != nil {
		return fmt.Errorf("create new config dir: %w", err)
	}
	src := filepath.Join(r.OldPath, configFileName)
	dst := filepath.Join(r.NewPath, configFileName)
	if fileExists(dst) {
		return nil // idempotent
	}
	return copyFileAtomic(src, dst)
}

func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // path from old config dir
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, FilePerm); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// fileExists distinguishes "not present" from other stat errors. A
// permission-denied (or any other non-IsNotExist) error must NOT silently
// degrade to "absent" — that would let an oddly-permissioned old dir
// collapse an old-only relocation to a no-op. Treat unknown errors as
// "present" so the relocation flow's subsequent open/read surfaces the
// real error instead of skipping the gate.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

// LoadForRuntime is the soft-conflict variant of Load for pure-read callers
// (config show, OpenNoMigrate). On ErrRelocationConflict it prints a one-shot
// stderr warning and returns the canonical (new-dir) config so the command
// can keep working — BUT only when a canonical config was actually read. If
// Load couldn't populate cfg (malformed YAML on the canonical side), the
// runtime must hard-fail instead of warning-and-defaulting; otherwise it
// would silently swap CredentialRef back to DefaultCredentialRef and mask
// the corrupt file (MON-5371 contract).
//
// Mutating callers (keychain.Open with §1.8 migration, config set, init
// post-gate) MUST use strict Load — under unresolved conflict the migration
// would scrub legacy + write canonical exactly the gate exists to prevent.
func LoadForRuntime() (*Config, error) {
	newDir, err := Dir()
	if err != nil {
		return nil, err
	}
	return loadForRuntimeFromNewDir(newDir)
}

// loadForRuntimeFromNewDir is the testable seam — LoadForRuntime and tests
// both call this. The unexported-seam pattern prevents the test-helper-as-
// parallel-implementation trap (slck MON-5372 lesson).
func loadForRuntimeFromNewDir(newDir string) (*Config, error) {
	cfg, err := loadFromNewDir(newDir)
	if err != nil && errors.Is(err, ErrRelocationConflict) && cfg != nil {
		warnReloConflictOnce(err)
		return cfg, nil
	}
	return cfg, err
}

var reloConflictOnce sync.Once

func warnReloConflictOnce(err error) {
	reloConflictOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "warning: %v; using the new config. Run `nrq init` to reconcile.\n", err)
	})
}
