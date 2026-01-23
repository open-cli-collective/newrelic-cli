package main

import (
	"errors"
	"os"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/alerts"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/apps"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/completion"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/configcmd"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/dashboards"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/deployments"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/entities"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/logs"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/nerdgraph"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/nrql"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/synthetics"
	"github.com/open-cli-collective/newrelic-cli/internal/cmd/users"
	"github.com/open-cli-collective/newrelic-cli/internal/exitcode"
)

func main() {
	// Register all commands
	root.RegisterCommands(
		alerts.Register,
		apps.Register,
		completion.Register,
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
		// Map error types to exit codes for shell scripting
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			os.Exit(exitcode.FromHTTPStatus(apiErr.StatusCode))
		}
		if errors.Is(err, api.ErrAPIKeyRequired) || errors.Is(err, api.ErrAccountIDRequired) {
			os.Exit(exitcode.ConfigError)
		}
		os.Exit(exitcode.GeneralError)
	}
}
