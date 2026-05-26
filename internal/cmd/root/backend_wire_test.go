package root

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	cccredstore "github.com/open-cli-collective/cli-common/credstore"

	"github.com/open-cli-collective/newrelic-cli/internal/keychain"
)

const serviceName = "newrelic-cli"

func resetState(t *testing.T) {
	t.Helper()
	keychain.SetBackendFlagOverride("", false)
	t.Cleanup(func() { keychain.SetBackendFlagOverride("", false) })
}

func newProbeCmd(name string) *cobra.Command {
	return &cobra.Command{Use: name, RunE: func(*cobra.Command, []string) error { return nil }}
}

func TestWireBackendSelection_FlagSet(t *testing.T) {
	resetState(t)
	t.Setenv(cccredstore.BackendEnvVar(serviceName), "")

	rootCmd, _ := NewRootCmd()
	rootCmd.AddCommand(newProbeCmd("probe"))
	rootCmd.SetArgs([]string{"probe", "--backend", "memory"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	v, set := keychain.GetBackendFlagOverride()
	if !set || v != "memory" {
		t.Errorf("override = (%q, %v); want (\"memory\", true)", v, set)
	}
}

func TestWireBackendSelection_FlagInvalid(t *testing.T) {
	resetState(t)
	t.Setenv(cccredstore.BackendEnvVar(serviceName), "")

	rootCmd, _ := NewRootCmd()
	rootCmd.AddCommand(newProbeCmd("probe"))
	rootCmd.SetArgs([]string{"probe", "--backend", "bogus"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, cccredstore.ErrBackendNotImplemented) {
		t.Errorf("errors.Is(_, ErrBackendNotImplemented) = false; err=%v", err)
	}
	if !strings.Contains(err.Error(), "backend") {
		t.Errorf("error should mention --backend: %v", err)
	}
}

func TestWireBackendSelection_ConfigPassthrough(t *testing.T) {
	t.Setenv(cccredstore.BackendEnvVar(serviceName), "")
	opts := &cccredstore.Options{}
	if err := cccredstore.BindBackendFlag(opts, "", false, "memory"); err != nil {
		t.Fatalf("BindBackendFlag: %v", err)
	}
	if opts.Backend != "" {
		t.Errorf("Backend = %q, want empty", opts.Backend)
	}
	if opts.ConfigBackend != cccredstore.BackendMemory {
		t.Errorf("ConfigBackend = %q, want %q", opts.ConfigBackend, cccredstore.BackendMemory)
	}
}

func TestWireBackendSelection_InvalidConfigDeferred(t *testing.T) {
	t.Setenv(cccredstore.BackendEnvVar(serviceName), "")
	opts := &cccredstore.Options{}
	if err := cccredstore.BindBackendFlag(opts, "", false, "bogus"); err != nil {
		t.Fatalf("BindBackendFlag should NOT validate config: %v", err)
	}
	if string(opts.ConfigBackend) != "bogus" {
		t.Errorf("ConfigBackend = %q, want verbatim %q", opts.ConfigBackend, "bogus")
	}
}

// TestWireBackendSelection_ShadowingSubcommand regresses the
// cobra-doesn't-chain-PersistentPreRunE bug. nrq has no shadowers
// today; the exported WireBackendSelection helper exists for this case.
func TestWireBackendSelection_ShadowingSubcommand(t *testing.T) {
	resetState(t)
	t.Setenv(cccredstore.BackendEnvVar(serviceName), "")

	rootCmd, _ := NewRootCmd()
	shadow := &cobra.Command{
		Use: "shadow",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return WireBackendSelection(cmd)
		},
	}
	shadow.AddCommand(newProbeCmd("leaf"))
	rootCmd.AddCommand(shadow)
	rootCmd.SetArgs([]string{"shadow", "leaf", "--backend", "memory"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	v, set := keychain.GetBackendFlagOverride()
	if !set || v != "memory" {
		t.Errorf("override = (%q, %v); want (\"memory\", true) — shadower's PreRunE failed to invoke WireBackendSelection", v, set)
	}
}
