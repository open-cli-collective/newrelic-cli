package main

import (
	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/alerts"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/apps"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/completion"
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

// buildRootCommand assembles the full nrq command tree. Extracted from
// main() so that real-tree tests can build the same tree main() builds,
// preventing test/main drift in the registrar list.
func buildRootCommand() (*cobra.Command, *root.Options) {
	rootCmd, opts := root.NewRootCmd()
	root.RegisterAll(rootCmd, opts,
		alerts.Register,
		apps.Register,
		completion.Register,
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
	return rootCmd, opts
}
