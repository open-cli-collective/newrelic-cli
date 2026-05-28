package root_test

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/alerts"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/apps"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/configcmd"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/dashboards"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/deployments"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/entities"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/initcmd"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/keys"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/logs"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/me"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/nerdgraph"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/nrql"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/synthetics"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/users"
)

// expectedJSONCarveOuts is the closed list of subcommand paths that declare a
// local --json flag. cli-common docs/output-and-rendering.md §2 reserves JSON
// for control-plane envelopes and passthrough surfaces. Every other leaf
// must be text-only (table/plain via -o, no --json flag).
//
// Adding to this list = expanding the carve-out. Don't add casually; the
// default is text-only.
var expectedJSONCarveOuts = map[string]bool{
	"nrq set-credential": true,
	"nrq config show":    true,
	"nrq config test":    true,
}

// TestJSONCarveOuts_Match enumerates every leaf command in the built tree
// and asserts the set with --json matches expectedJSONCarveOuts exactly.
// Catches both regressions (a resource leaf grows a --json) and silent
// scope creep (a new diagnostic adds --json without updating the list).
func TestJSONCarveOuts_Match(t *testing.T) {
	// Mirror the full set of registrations from cmd/nrq/main.go so the test
	// is truly exhaustive — any future --json added under, say, initcmd
	// would otherwise silently bypass this enforcement check.
	rootCmd, _ := root.NewRootCmd()
	root.RegisterAll(rootCmd, &root.Options{},
		alerts.Register,
		apps.Register,
		configcmd.Register,
		dashboards.Register,
		deployments.Register,
		entities.Register,
		initcmd.Register,
		keys.Register,
		logs.Register,
		me.Register,
		nerdgraph.Register,
		nrql.Register,
		synthetics.Register,
		users.Register,
	)

	got := map[string]bool{}
	walk(rootCmd, func(c *cobra.Command) {
		// Leaves only (Runnable). Group commands like `nrq config` don't run.
		if !c.Runnable() {
			return
		}
		if c.Flags().Lookup("json") != nil {
			got[commandPath(c)] = true
		}
	})

	for p := range expectedJSONCarveOuts {
		if !got[p] {
			t.Errorf("expected --json carve-out missing: %s", p)
		}
	}
	for p := range got {
		if !expectedJSONCarveOuts[p] {
			t.Errorf("unexpected --json flag on %s — cli-common §2 reserves JSON "+
				"for control-plane envelopes; add to expectedJSONCarveOuts only if "+
				"this is a deliberate scope decision", p)
		}
	}
}

// walk traverses the command tree depth-first, calling fn on every node.
func walk(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, child := range c.Commands() {
		walk(child, fn)
	}
}

// commandPath returns the full space-separated path (e.g. "nrq config show").
func commandPath(c *cobra.Command) string {
	parts := []string{c.Name()}
	for p := c.Parent(); p != nil; p = p.Parent() {
		parts = append([]string{p.Name()}, parts...)
	}
	return strings.Join(parts, " ")
}
