package main

import (
	"os"

	"github.com/piekstra/newrelic-cli/internal/cmd/alerts"
	"github.com/piekstra/newrelic-cli/internal/cmd/apps"
	"github.com/piekstra/newrelic-cli/internal/cmd/configcmd"
	"github.com/piekstra/newrelic-cli/internal/cmd/dashboards"
	"github.com/piekstra/newrelic-cli/internal/cmd/deployments"
	"github.com/piekstra/newrelic-cli/internal/cmd/entities"
	"github.com/piekstra/newrelic-cli/internal/cmd/logs"
	"github.com/piekstra/newrelic-cli/internal/cmd/nerdgraph"
	"github.com/piekstra/newrelic-cli/internal/cmd/nrql"
	"github.com/piekstra/newrelic-cli/internal/cmd/root"
	"github.com/piekstra/newrelic-cli/internal/cmd/synthetics"
	"github.com/piekstra/newrelic-cli/internal/cmd/users"
)

func main() {
	// Register all commands
	root.RegisterCommands(
		alerts.Register,
		apps.Register,
		configcmd.Register,
		dashboards.Register,
		deployments.Register,
		entities.Register,
		logs.Register,
		nerdgraph.Register,
		nrql.Register,
		synthetics.Register,
		users.Register,
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
