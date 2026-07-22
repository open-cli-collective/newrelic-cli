package apps

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/open-cli-collective/newrelic-cli/internal/cmd/root"
)

func newGetCmd(opts *root.Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <app>",
		Short: "Get details for a specific application",
		Long: `Get detailed information about a specific APM application.

The application can be identified by numeric app ID, name, or entity GUID.

Displays ID, name, language, alert status, reporting status, and the time
reporting last changed. Alert status values come from NerdGraph:
NOT_ALERTING, WARNING, CRITICAL, NOT_CONFIGURED.`,
		Example: `  nrq apps get 12345678
  nrq apps get "my-production-app"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(opts, args[0])
		},
	}
}

func runGet(opts *root.Options, appID string) error {
	client, err := opts.APIClient()
	if err != nil {
		return err
	}

	app, err := client.GetApplication(appID)
	if err != nil {
		return err
	}

	v := opts.View()

	switch v.Format {
	case "plain":
		return v.Plain([][]string{
			{fmt.Sprintf("%d", app.ID), app.Name, app.Language, app.HealthStatus},
		})
	default:
		v.Print("ID:              %d\n", app.ID)
		v.Print("GUID:            %s\n", app.GUID)
		v.Print("Name:            %s\n", app.Name)
		v.Print("Language:        %s\n", app.Language)
		v.Print("Alert Status:    %s\n", app.HealthStatus)
		v.Print("Reporting:       %t\n", app.Reporting)
		v.Print("Status Changed:  %s\n", app.LastReportedAt)
		return nil
	}
}
