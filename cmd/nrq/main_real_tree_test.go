package main

import (
	"testing"

	"github.com/spf13/cobra"

	cccredstore "github.com/open-cli-collective/cli-common/credstore"
)

// TestRealCommandTreeInheritsBackendFlag walks the full nrq command
// tree (built via the same buildRootCommand() main() uses) and asserts
// that every leaf resolves --backend to the same *pflag.Flag pointer as
// the root's PersistentFlags entry. Pointer-identity catches a leaf
// that locally shadows --backend with its own string flag.
//
// Lives in package main (not internal/cmd/root) because root cannot
// import the registrars without creating an import cycle — each
// registrar already imports internal/cmd/root.
func TestRealCommandTreeInheritsBackendFlag(t *testing.T) {
	rootCmd, _ := buildRootCommand()
	canonical := rootCmd.PersistentFlags().Lookup(cccredstore.BackendFlagName)
	if canonical == nil {
		t.Fatalf("root persistent flag --%s not registered", cccredstore.BackendFlagName)
	}

	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		children := c.Commands()
		if len(children) == 0 {
			got := c.Flag(cccredstore.BackendFlagName)
			if got == nil {
				t.Errorf("%q: cmd.Flag(--%s) returned nil", c.CommandPath(), cccredstore.BackendFlagName)
				return
			}
			if got != canonical {
				t.Errorf("%q: cmd.Flag(--%s) pointer = %p, want canonical %p (local shadowing?)",
					c.CommandPath(), cccredstore.BackendFlagName, got, canonical)
			}
			return
		}
		for _, child := range children {
			walk(child)
		}
	}
	walk(rootCmd)
}
